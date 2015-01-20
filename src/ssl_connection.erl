%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2007-2013. All Rights Reserved.
%%
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%%
%% %CopyrightEnd%
%%

%%
%%----------------------------------------------------------------------
%% Purpose: Handles an ssl connection, e.i. both the setup
%% e.i. SSL-Handshake, SSL-Alert and SSL-Cipher protocols and delivering
%% data to the application. All data on the connectinon is received and 
%% sent according to the SSL-record protocol.  
%%----------------------------------------------------------------------

-module(ssl_connection).

-behaviour(gen_fsm).

-include("ssl_handshake.hrl").
-include("ssl_alert.hrl").
-include("ssl_record.hrl").
-include("ssl_cipher.hrl"). 
-include("ssl_internal.hrl").
-include("ssl_srp.hrl").
-include("ssl_srp_primes.hrl").
-include_lib("public_key/include/public_key.hrl"). 

%% Internal application API
-export([send/2, recv/3, connect/7, ssl_accept/6, handshake/2,
	 socket_control/3, close/1, shutdown/2,
	 new_user/2, get_opts/2, set_opts/2, info/1, session_info/1, 
	 peer_certificate/1, renegotiation/1, negotiated_next_protocol/1, prf/5]).

%% Called by ssl_connection_sup
-export([start_link/7]). 

%% gen_fsm callbacks
-export([init/1, hello/2, certify/2, cipher/2,
	 abbreviated/2, connection/2, handle_event/3,
         handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

-record(message_sequences, {
	  read = 0,
	  write = 0
	 }).

-record(state, {
          role,               % client | server
          user_application,   % {MonitorRef, pid()} 
          connection_type,    % stream | datagram
          transport_cb,       % atom() - callback module 
          data_tag,           % atom()  - ex tcp.
	  close_tag,          % atom()  - ex tcp_closed
	  error_tag,          % atom() - ex  tcp_error
          host,               % string() | ipadress()
          port,               % integer()
          socket,             % socket() 
          ssl_options,        % #ssl_options{}
          socket_options,     % #socket_options{}
          connection_states,  % #connection_states{} from ssl_record.hrl
	  message_sequences = #message_sequences{},
	  tls_packets = [],        % Not yet handled decode ssl/tls packets.
          tls_record_buffer,  % binary() buffer of incomplete records
          tls_handshake_buffer, % binary() buffer of incomplete handshakes
          dtls_handshake_buffer, % buffer of incomplete DTLS handshakes
          tls_handshake_history, % tls_handshake_history()
          tls_cipher_texts,     % list() received but not deciphered yet
          tls_cipher_texts_next,% list() received for Epoch not yet active
	  dtls_retransmit_timer,
	  last_retransmit,
	  last_read_seq,
	  msl_timer,
	  flight_state,
	  flight_buffer,        % buffer of not yet ACKed TLS records
	  cert_db,              %
          session,              % #session{} from ssl_handshake.hrl
	  session_cache,        % 
	  session_cache_cb,     %
          negotiated_version,   % tls_version()
          client_certificate_requested = false,
	  key_algorithm,       % atom as defined by cipher_suite
	  hashsign_algorithm,  % atom as defined by cipher_suite
          public_key_info,     % PKIX: {Algorithm, PublicKey, PublicKeyParams}
          private_key,         % PKIX: #'RSAPrivateKey'{}
	  diffie_hellman_params, % PKIX: #'DHParameter'{} relevant for server side
	  diffie_hellman_keys, % {PublicKey, PrivateKey}
	  psk_identity,        % binary() - server psk identity hint
	  srp_params,          % #srp_user{}
	  srp_keys,            % {PublicKey, PrivateKey}
          premaster_secret,    %
	  file_ref_db,         % ets()
          cert_db_ref,         % ref()
          bytes_to_read,       % integer(), # bytes to read in passive mode
          user_data_buffer,    % binary()
	  log_alert,           % boolean() 
	  renegotiation,       % {boolean(), From | internal | peer}
	  start_or_recv_from,  % "gen_fsm From"
	  timer,               % start_or_recv_timer
	  send_queue,          % queue()
	  terminated = false,  %
	  allow_renegotiate = true,
	  change_cipher_spec = {false, false}:: {Expect :: boolean(), Got :: boolean()},
          expecting_next_protocol_negotiation = false :: boolean(),
          next_protocol = undefined :: undefined | binary(),
	  client_ecc,          % {Curves, PointFmt}
	  client_cookie = <<>>
	 }).

-define(DEFAULT_DIFFIE_HELLMAN_PARAMS, 
	#'DHParameter'{prime = ?DEFAULT_DIFFIE_HELLMAN_PRIME,
		       base = ?DEFAULT_DIFFIE_HELLMAN_GENERATOR}).
-define(WAIT_TO_ALLOW_RENEGOTIATION, 12000).
-define(IS_HANDSHAKE_MSG(Msg),
	(is_record(hello_request) orelse
	 is_record(client_hello, Msg) orelse
	 is_record(server_hello, Msg) orelse
	 is_record(hello_verify_request, Msg) orelse
	 is_record(certificate) orelse
	 is_record(server_key_exchange) orelse
	 is_record(certificate_request) orelse
	 is_record(server_hello_done) orelse
	 is_record(certificate_verify) orelse
	 is_record(client_key_exchange) orelse
	 is_record(finished)).

-type state_name()           :: hello | abbreviated | certify | cipher | connection.
-type gen_fsm_state_return() :: {next_state, state_name(), #state{}} |
				{next_state, state_name(), #state{}, timeout()} |
				{stop, term(), #state{}}.

%%====================================================================
%% Internal application API
%%====================================================================	     

%%--------------------------------------------------------------------
-spec send(pid(), iodata()) -> ok | {error, reason()}.
%%
%% Description: Sends data over the ssl connection
%%--------------------------------------------------------------------
send(Pid, Data) -> 
    sync_send_all_state_event(Pid, {application_data, 
				    %% iolist_to_binary should really
				    %% be called iodata_to_binary()
				    erlang:iolist_to_binary(Data)}).

%%--------------------------------------------------------------------
-spec recv(pid(), integer(), timeout()) ->  
    {ok, binary() | list()} | {error, reason()}.
%%
%% Description:  Receives data when active = false
%%--------------------------------------------------------------------
recv(Pid, Length, Timeout) -> 
    sync_send_all_state_event(Pid, {recv, Length, Timeout}).
%%--------------------------------------------------------------------
-spec connect(host(), inet:port_number(), port(), {#ssl_options{}, #socket_options{}},
	      pid(), tuple(), timeout()) ->
		     {ok, #sslsocket{}} | {error, reason()}.
%%
%% Description: Connect to an ssl server.
%%--------------------------------------------------------------------
connect(Host, Port, Socket, Options, User, CbInfo, Timeout) ->
    try start_fsm(client, Host, Port, Socket, Options, User, CbInfo,
		  Timeout)
    catch
	exit:{noproc, _} ->
	    {error, ssl_not_started}
    end.
%%--------------------------------------------------------------------
-spec ssl_accept(inet:port_number(), port(), {#ssl_options{}, #socket_options{}},
				      pid(), tuple(), timeout()) ->
    {ok, #sslsocket{}} | {error, reason()}.
%%
%% Description: Performs accept on an ssl listen socket. e.i. performs
%%              ssl handshake. 
%%--------------------------------------------------------------------
ssl_accept(Port, Socket, Opts, User, CbInfo, Timeout) ->
    try start_fsm(server, "localhost", Port, Socket, Opts, User, 
		  CbInfo, Timeout)
    catch
	exit:{noproc, _} ->
	    {error, ssl_not_started}
    end.	

%%--------------------------------------------------------------------
-spec handshake(#sslsocket{}, timeout()) ->  ok | {error, reason()}.
%%
%% Description: Starts ssl handshake. 
%%--------------------------------------------------------------------
handshake(#sslsocket{pid = Pid}, Timeout) ->  
    case sync_send_all_state_event(Pid, {start, Timeout}) of
	connected ->
	    ok;
 	Error ->
	    Error
    end.
%--------------------------------------------------------------------
-spec socket_control(port(), pid(), atom()) -> 
    {ok, #sslsocket{}} | {error, reason()}.  
%%
%% Description: Set the ssl process to own the accept socket
%%--------------------------------------------------------------------	    
socket_control(Socket, Pid, Transport) ->
    case Transport:controlling_process(Socket, Pid) of
	ok ->
	    {ok, ssl_socket:socket(Pid, Transport, Socket)};
	{error, Reason}	->
	    {error, Reason}
    end.

%%--------------------------------------------------------------------
-spec close(pid()) -> ok | {error, reason()}.  
%%
%% Description:  Close an ssl connection
%%--------------------------------------------------------------------
close(ConnectionPid) ->
    case sync_send_all_state_event(ConnectionPid, close) of
	{error, closed} ->
	    ok;
	Other ->
	    Other
    end.

%%--------------------------------------------------------------------
-spec shutdown(pid(), atom()) -> ok | {error, reason()}.  
%%
%% Description: Same as gen_tcp:shutdown/2
%%--------------------------------------------------------------------
shutdown(ConnectionPid, How) ->
    sync_send_all_state_event(ConnectionPid, {shutdown, How}).

%%--------------------------------------------------------------------
-spec new_user(pid(), pid()) ->  ok | {error, reason()}.
%%
%% Description:  Changes process that receives the messages when active = true
%% or once. 
%%--------------------------------------------------------------------
new_user(ConnectionPid, User) ->
    sync_send_all_state_event(ConnectionPid, {new_user, User}).

%%--------------------------------------------------------------------
-spec negotiated_next_protocol(pid()) -> {ok, binary()} | {error, reason()}.
%%
%% Description:  Returns the negotiated protocol
%%--------------------------------------------------------------------
negotiated_next_protocol(ConnectionPid) ->
    sync_send_all_state_event(ConnectionPid, negotiated_next_protocol).

%%--------------------------------------------------------------------
-spec get_opts(pid(), list()) -> {ok, list()} | {error, reason()}.    
%%
%% Description: Same as inet:getopts/2
%%--------------------------------------------------------------------
get_opts(ConnectionPid, OptTags) ->
    sync_send_all_state_event(ConnectionPid, {get_opts, OptTags}).
%%--------------------------------------------------------------------
-spec set_opts(pid(), list()) -> ok | {error, reason()}. 
%%
%% Description:  Same as inet:setopts/2
%%--------------------------------------------------------------------
set_opts(ConnectionPid, Options) ->
    sync_send_all_state_event(ConnectionPid, {set_opts, Options}).

%%--------------------------------------------------------------------
-spec info(pid()) ->  {ok, {atom(), tuple()}} | {error, reason()}. 
%%
%% Description:  Returns ssl protocol and cipher used for the connection
%%--------------------------------------------------------------------
info(ConnectionPid) ->
    sync_send_all_state_event(ConnectionPid, info). 

%%--------------------------------------------------------------------
-spec session_info(pid()) -> {ok, list()} | {error, reason()}. 
%%
%% Description:  Returns info about the ssl session
%%--------------------------------------------------------------------
session_info(ConnectionPid) ->
    sync_send_all_state_event(ConnectionPid, session_info). 

%%--------------------------------------------------------------------
-spec peer_certificate(pid()) -> {ok, binary()| undefined} | {error, reason()}.
%%
%% Description: Returns the peer cert
%%--------------------------------------------------------------------
peer_certificate(ConnectionPid) ->
    sync_send_all_state_event(ConnectionPid, peer_certificate). 

%%--------------------------------------------------------------------
-spec renegotiation(pid()) -> ok | {error, reason()}.
%%
%% Description: Starts a renegotiation of the ssl session.
%%--------------------------------------------------------------------
renegotiation(ConnectionPid) ->
    sync_send_all_state_event(ConnectionPid, renegotiate). 

%%--------------------------------------------------------------------
-spec prf(pid(), binary() | 'master_secret', binary(),
	  binary() | ssl:prf_random(), non_neg_integer()) ->
		 {ok, binary()} | {error, reason()} | {'EXIT', term()}.
%%
%% Description: use a ssl sessions TLS PRF to generate key material
%%--------------------------------------------------------------------
prf(ConnectionPid, Secret, Label, Seed, WantedLength) ->
    sync_send_all_state_event(ConnectionPid, {prf, Secret, Label, Seed, WantedLength}).

%%====================================================================
%% ssl_connection_sup API
%%====================================================================

%%--------------------------------------------------------------------
-spec start_link(atom(), host(), inet:port_number(), port(), list(), pid(), tuple()) ->
    {ok, pid()} | ignore |  {error, reason()}.
%%
%% Description: Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this function
%% does not return until Module:init/1 has returned.  
%%--------------------------------------------------------------------
start_link(Role, Host, Port, Socket, Options, User, CbInfo) ->
    {ok, proc_lib:spawn_link(?MODULE, init, [[Role, Host, Port, Socket, Options, User, CbInfo]])}.

init([Role, Host, Port, Socket, {SSLOpts0, _} = Options,  User, CbInfo]) ->
    State0 = initial_state(Role, Host, Port, Socket, Options, User, CbInfo),
    Handshake = ssl_handshake:init_handshake_history(),
    TimeStamp = calendar:datetime_to_gregorian_seconds({date(), time()}),
    try ssl_init(SSLOpts0, Role) of
	{ok, Ref, CertDbHandle, FileRefHandle, CacheHandle, OwnCert, Key, DHParams} ->
	    Session = State0#state.session,
	    State1 = State0#state{
				 tls_handshake_history = Handshake,
				 session = Session#session{own_certificate = OwnCert,
							   time_stamp = TimeStamp},
				 file_ref_db = FileRefHandle,
				 cert_db_ref = Ref,
				 cert_db = CertDbHandle,
				 session_cache = CacheHandle,
				 private_key = Key,
				 diffie_hellman_params = DHParams},
	    State = start_flight(undefined, State1),
	    gen_fsm:enter_loop(?MODULE, [], hello, State, get_timeout(State))
    catch
	throw:Error ->
	    gen_fsm:enter_loop(?MODULE, [], error, {Error,State0}, get_timeout(State0))
    end.

%%--------------------------------------------------------------------
%% Description:There should be one instance of this function for each
%% possible state name. Whenever a gen_fsm receives an event sent
%% using gen_fsm:send_event/2, the instance of this function with the
%% same name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%

%%--------------------------------------------------------------------
-spec hello(start | #hello_request{} | #client_hello{} | #server_hello{} | term(),
	    #state{}) -> gen_fsm_state_return().    
%%--------------------------------------------------------------------
hello(start, #state{host = Host, port = Port, role = client,
			      ssl_options = SslOpts, 
			      session = #session{own_certificate = Cert} = Session0,
			      session_cache = Cache, session_cache_cb = CacheCb,
			      connection_states = ConnectionStates0,
			      renegotiation = {Renegotiation, _},
			      client_cookie = Cookie} = State0) ->
    Hello = ssl_handshake:client_hello(Host, Port, Cookie, ConnectionStates0, SslOpts,
				       Cache, CacheCb, Renegotiation, Cert),
    
    Version = Hello#client_hello.client_version,
    State1 = State0#state{negotiated_version = Version, %% Requested version
			  session =
			      Session0#session{session_id = Hello#client_hello.session_id},
			  tls_handshake_history = ssl_handshake:init_handshake_history()},

    State2 = send_flight(Hello, waiting, State1),

    {Record, State} = next_record(State2),
    next_state(hello, hello, Record, State);

hello(start, #state{role = server} = State0) ->
    {Record, State} = next_record(State0),
    next_state(hello, hello, Record, State);

hello(#hello_request{}, #state{role = client} = State0) ->
    {Record, State} = next_record(State0),
    next_state(hello, hello, Record, State);

hello(#server_hello{cipher_suite = CipherSuite,
		    compression_method = Compression} = Hello,
      #state{session = #session{session_id = OldId},
	     connection_states = ConnectionStates0,
	     role = client,
	     negotiated_version = ReqVersion,
	     renegotiation = {Renegotiation, _},
	     ssl_options = SslOptions} = State1) ->
    State0 = flight_done(State1),
    case ssl_handshake:hello(Hello, SslOptions, ConnectionStates0, Renegotiation) of
	#alert{} = Alert ->
	    handle_own_alert(Alert, ReqVersion, hello, State0);
	{Version, NewId, ConnectionStates, NextProtocol} ->
	    {KeyAlgorithm, _, _, _} =
		ssl_cipher:suite_definition(CipherSuite),

	    PremasterSecret = make_premaster_secret(ReqVersion, KeyAlgorithm),
	    
	    NewNextProtocol = case NextProtocol of
				  undefined ->
				      State0#state.next_protocol;
				  _ ->
				      NextProtocol
			      end,
	    
	    State = State0#state{key_algorithm = KeyAlgorithm,
				 hashsign_algorithm = default_hashsign(Version, KeyAlgorithm),
				 negotiated_version = Version,
				 connection_states = ConnectionStates,
				 premaster_secret = PremasterSecret,
				 expecting_next_protocol_negotiation = NextProtocol =/= undefined,
				 next_protocol = NewNextProtocol},
	    
	    case ssl_session:is_new(OldId, NewId) of
		true ->
		    handle_new_session(NewId, CipherSuite, Compression,
				       State#state{connection_states = ConnectionStates});
		false ->
		    handle_resumed_session(NewId, State#state{connection_states = ConnectionStates}) 
	    end
    end;

hello(#hello_verify_request{cookie = Cookie},
      #state{host = Host, port = Port,
	     session = #session{own_certificate = Cert},
	     session_cache = Cache, session_cache_cb = CacheCb,
	     ssl_options = SslOpts,
	     connection_states = ConnectionStates0,
	     renegotiation = {Renegotiation, _}} = State0) ->
    Hello = ssl_handshake:client_hello(Host, Port, Cookie, ConnectionStates0, SslOpts,
				       Cache, CacheCb, Renegotiation, Cert),
    State1 = State0#state{
	       tls_handshake_history = ssl_handshake:init_handshake_history(),
	       client_cookie = Cookie},
    State2 = send_flight(Hello, waiting, State1),

    {Record, State} = next_record(State2),
    next_state(hello, hello, Record, State);

hello(Hello = #client_hello{client_version = ClientVersion},
      State = #state{connection_states = ConnectionStates0,
		     port = Port, session = #session{own_certificate = Cert} = Session0,
		     renegotiation = {Renegotiation, _},
		     session_cache = Cache,
		     session_cache_cb = CacheCb,
		     ssl_options = SslOpts}) ->
    case ssl_handshake:hello(Hello, SslOpts, {Port, Session0, Cache, CacheCb,
				     ConnectionStates0, Cert}, Renegotiation) of
        {Version, {Type, Session}, ConnectionStates, ProtocolsToAdvertise,
	 EcPointFormats, EllipticCurves} ->
            do_server_hello(Type, ProtocolsToAdvertise,
			    EcPointFormats, EllipticCurves,
			    State#state{connection_states  = ConnectionStates,
					negotiated_version = Version,
					session = Session,
					client_ecc = {EllipticCurves, EcPointFormats}});
        #alert{} = Alert ->
            handle_own_alert(Alert, ClientVersion, hello, State)
    end;

hello(timeout, State) ->
    { next_state, hello, State, hibernate };

%% hello(Msg, #state{negotiated_version = {254, _}} = State0)
%%   when ?IS_HANDSHAKE_MSG(Msg) ->
%%     %% ignore unexpeced handshake message in DTLS, this is almost
%%     %% certainly a old message
%%     {Record, State} = next_record(State0),
%%     next_state(hello, hello, Record, State);

hello(Msg, State) ->
    handle_unexpected_message(Msg, hello, State).
%%--------------------------------------------------------------------
-spec abbreviated(#hello_request{} | #finished{} | term(),
		  #state{}) -> gen_fsm_state_return().   
%%--------------------------------------------------------------------
abbreviated(#hello_request{}, State0) ->
    {Record, State} = next_record(State0),
    next_state(abbreviated, hello, Record, State);

abbreviated(#finished{verify_data = Data} = Finished,
	    #state{role = server,
		   negotiated_version = Version,
		   tls_handshake_history = Handshake,
		   session = #session{master_secret = MasterSecret},
		  connection_states = ConnectionStates0} = 
	    State0) ->
    State = flight_done(State0),
    case ssl_handshake:verify_connection(Version, Finished, client,
					 get_current_connection_state_prf(ConnectionStates0, write),
					 MasterSecret, Handshake) of
        verified ->  
	    ConnectionStates = ssl_record:set_client_verify_data(current_both, Data, ConnectionStates0),
	    next_state_connection(abbreviated, 
				  ack_connection(State#state{connection_states = ConnectionStates}));
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, abbreviated, State)
    end;

abbreviated(#finished{verify_data = Data} = Finished,
	    #state{role = client, tls_handshake_history = Handshake0,
		   session = #session{master_secret = MasterSecret},
		   negotiated_version = Version,
		   connection_states = ConnectionStates0} = State0) ->
    State = flight_done(State0),
    case ssl_handshake:verify_connection(Version, Finished, server,
					 get_pending_connection_state_prf(ConnectionStates0, write),
					 MasterSecret, Handshake0) of
        verified ->
	    ConnectionStates1 = ssl_record:set_server_verify_data(current_read, Data, ConnectionStates0),
	    State1 =
		finalize_handshake(State#state{connection_states = ConnectionStates1}, abbreviated, finished),
	    next_state_connection(abbreviated, ack_connection(State1));
        #alert{} = Alert ->
	    handle_own_alert(Alert, Version, abbreviated, State)
    end;

%% only allowed to send next_protocol message after change cipher spec
%% & before finished message and it is not allowed during renegotiation
abbreviated(#next_protocol{selected_protocol = SelectedProtocol},
	    #state{role = server, expecting_next_protocol_negotiation = true} = State0) ->
    {Record, State} = next_record(State0#state{next_protocol = SelectedProtocol}),
    next_state(abbreviated, abbreviated, Record, State);

abbreviated(timeout, State) ->
    { next_state, abbreviated, State, hibernate };

abbreviated(Msg, State) ->
    handle_unexpected_message(Msg, abbreviated, State).

%%--------------------------------------------------------------------
-spec certify(#hello_request{} | #certificate{} |  #server_key_exchange{} |
	      #certificate_request{} | #server_hello_done{} | #client_key_exchange{} | term(),
	      #state{}) -> gen_fsm_state_return().   
%%--------------------------------------------------------------------
certify(#hello_request{}, State0) ->
    {Record, State} = next_record(State0),
    next_state(certify, hello, Record, State);

certify(#certificate{asn1_certificates = []}, 
	#state{role = server, negotiated_version = Version,
	       ssl_options = #ssl_options{verify = verify_peer,
					  fail_if_no_peer_cert = true}} = 
	State) ->
    Alert =  ?ALERT_REC(?FATAL,?HANDSHAKE_FAILURE),
    handle_own_alert(Alert, Version, certify, State);

certify(#certificate{asn1_certificates = []}, 
	#state{role = server,
	       ssl_options = #ssl_options{verify = verify_peer,
					  fail_if_no_peer_cert = false}} = 
	State0) ->
    {Record, State} = next_record(State0#state{client_certificate_requested = false}),
    next_state(certify, certify, Record, State);

certify(#certificate{} = Cert, 
        #state{negotiated_version = Version,
	       role = Role,
	       cert_db = CertDbHandle,
	       cert_db_ref = CertDbRef,
	       ssl_options = Opts} = State) ->
    case ssl_handshake:certify(Cert, CertDbHandle, CertDbRef, Opts#ssl_options.depth,
			       Opts#ssl_options.verify,
			       Opts#ssl_options.verify_fun, Role) of
        {PeerCert, PublicKeyInfo} ->
	    handle_peer_cert(PeerCert, PublicKeyInfo, 
			     State#state{client_certificate_requested = false});
	#alert{} = Alert ->
            handle_own_alert(Alert, Version, certify, State)
    end;

certify(#server_key_exchange{} = KeyExchangeMsg, 
        #state{role = client, negotiated_version = Version,
	       key_algorithm = Alg} = State0) 
  when Alg == dhe_dss; Alg == dhe_rsa;
       Alg == ecdhe_rsa; Alg == ecdhe_ecdsa;
       Alg == dh_anon; Alg == ecdh_anon;
       Alg == psk; Alg == ecdhe_psk; Alg == dhe_psk; Alg == rsa_psk;
       Alg == srp_dss; Alg == srp_rsa; Alg == srp_anon ->
    case handle_server_key(KeyExchangeMsg, State0) of
	#state{} = State1 ->
	    {Record, State} = next_record(State1),
	    next_state(certify, certify, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end;

certify(#server_key_exchange{} = Msg, 
        #state{role = client, key_algorithm = rsa} = State) -> 
    handle_unexpected_message(Msg, certify_server_keyexchange, State);

certify(#certificate_request{},
	#state{negotiated_version = Version,
	       key_algorithm = Alg} = State)
  when Alg == dh_anon; Alg == ecdh_anon;
       Alg == psk; Alg == ecdhe_psk; Alg == dhe_psk; Alg == rsa_psk;
       Alg == srp_dss; Alg == srp_rsa; Alg == srp_anon ->

    Alert =  ?ALERT_REC(?FATAL,?HANDSHAKE_FAILURE),
    handle_own_alert(Alert, Version, certify, State);

certify(#certificate_request{}, State0) ->
    {Record, State} = next_record(State0#state{client_certificate_requested = true}),
    next_state(certify, certify, Record, State);

%% PSK and RSA_PSK might bypass the Server-Key-Exchange
certify(#server_hello_done{},
	#state{session = #session{master_secret = undefined},
	       negotiated_version = Version,
	       psk_identity = PSKIdentity,
	       premaster_secret = undefined,
	       role = client,
	       key_algorithm = Alg} = State0)
  when Alg == psk ->
    State1 = flight_done(State0),
    case server_psk_master_secret(PSKIdentity, State1) of
	#state{} = State ->
	    client_certify_and_key_exchange(State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State1)
    end;

certify(#server_hello_done{},
	#state{session = #session{master_secret = undefined},
	       ssl_options = SslOpts,
	       negotiated_version = Version,
	       psk_identity = PSKIdentity,
	       premaster_secret = undefined,
	       role = client,
	       key_algorithm = Alg} = State0)
  when Alg == rsa_psk ->
    State1 = flight_done(State0),
    case handle_psk_identity(PSKIdentity, SslOpts#ssl_options.user_lookup_fun) of
	{ok, PSK} when is_binary(PSK) ->
	    PremasterSecret = make_premaster_secret(Version, rsa),
	    Len = byte_size(PSK),
	    RealPMS = <<?UINT16(48), PremasterSecret/binary, ?UINT16(Len), PSK/binary>>,
	    State2 = State1#state{premaster_secret = PremasterSecret},
	    State = master_from_premaster_secret(RealPMS, State2),
	    client_certify_and_key_exchange(State);
	#alert{} = Alert ->
	    Alert;
	_ ->
	    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER)
    end;

%% Master secret was determined with help of server-key exchange msg
certify(#server_hello_done{},
	#state{session = #session{master_secret = MasterSecret} = Session,
	       connection_states = ConnectionStates0,
	       negotiated_version = Version,
	       premaster_secret = undefined,
	       role = client} = State0) ->
    State1 = flight_done(State0),
    case ssl_handshake:master_secret(Version, Session, 
				     ConnectionStates0, client) of
	{MasterSecret, ConnectionStates} ->
	    State = State1#state{connection_states = ConnectionStates},
	    client_certify_and_key_exchange(State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State1)
    end;

%% Master secret is calculated from premaster_secret
certify(#server_hello_done{},
	#state{session = Session0,
	       connection_states = ConnectionStates0,
	       negotiated_version = Version,
	       premaster_secret = PremasterSecret,
	       role = client} = State0) ->    
    State1 = flight_done(State0),
    case ssl_handshake:master_secret(Version, PremasterSecret, 
				     ConnectionStates0, client) of
	{MasterSecret, ConnectionStates} ->
	    Session = Session0#session{master_secret = MasterSecret},
	    State = State1#state{connection_states = ConnectionStates,
				 session = Session},
	    client_certify_and_key_exchange(State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State1)
    end;

certify(#client_key_exchange{} = Msg,
	#state{role = server,
	       client_certificate_requested = true,
	       ssl_options = #ssl_options{fail_if_no_peer_cert = true}} = State) ->
    %% We expect a certificate here
    handle_unexpected_message(Msg, certify_client_key_exchange, State);

certify(#client_key_exchange{exchange_keys = Keys},
	State0 = #state{key_algorithm = KeyAlg, negotiated_version = Version}) ->
    State = expect_cipher_state_change(State0),
    try
	certify_client_key_exchange(ssl_handshake:decode_client_key(Keys, KeyAlg, Version), State)
    catch 
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State)
    end;


certify(timeout, State) ->
    { next_state, certify, State, hibernate };

certify(Msg, State) ->
    handle_unexpected_message(Msg, certify, State).

certify_client_key_exchange(#encrypted_premaster_secret{premaster_secret= EncPMS},
			    #state{negotiated_version = Version,
				   connection_states = ConnectionStates0,
				   session = Session0,
				   private_key = Key} = State0) ->
    PremasterSecret = ssl_handshake:decrypt_premaster_secret(EncPMS, Key),
    case ssl_handshake:master_secret(Version, PremasterSecret,
				     ConnectionStates0, server) of
	{MasterSecret, ConnectionStates} ->
	    Session = Session0#session{master_secret = MasterSecret},
	    State1 = State0#state{connection_states = ConnectionStates,
				  session = Session},
	    {Record, State} = next_record(State1),
	    next_state(certify, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end;

certify_client_key_exchange(#client_diffie_hellman_public{dh_public = ClientPublicDhKey},
			    #state{negotiated_version = Version,
				   diffie_hellman_params = #'DHParameter'{} = Params,
				   diffie_hellman_keys = {_, ServerDhPrivateKey}} = State0) ->
    case dh_master_secret(Params, ClientPublicDhKey, ServerDhPrivateKey, State0) of
	#state{} = State1 ->
	    {Record, State} = next_record(State1),
	    next_state(certify, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end;

certify_client_key_exchange(#client_ec_diffie_hellman_public{dh_public = ClientPublicEcDhPoint},
			    #state{negotiated_version = Version,
				   diffie_hellman_keys = ECDHKey} = State0) ->
    case ec_dh_master_secret(ECDHKey, #'ECPoint'{point = ClientPublicEcDhPoint}, State0) of
	#state{} = State1 ->
	    {Record, State} = next_record(State1),
	    next_state(certify, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end;

certify_client_key_exchange(#client_psk_identity{identity = ClientPSKIdentity},
			    #state{negotiated_version = Version} = State0) ->
    case server_psk_master_secret(ClientPSKIdentity, State0) of
	#state{} = State1 ->
	    {Record, State} = next_record(State1),
	    next_state(certify, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end;

certify_client_key_exchange(#client_ecdhe_psk_identity{
			       identity =  ClientPSKIdentity,
			       dh_public = ClientPublicEcDhPoint},
			    #state{negotiated_version = Version,
				   diffie_hellman_keys = ECDHKey} = State0) ->
    case ecdhe_psk_master_secret(ClientPSKIdentity, ECDHKey, #'ECPoint'{point = ClientPublicEcDhPoint}, State0) of
	#state{} = State1 ->
	    {Record, State} = next_record(State1),
	    next_state(certify, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end;

certify_client_key_exchange(#client_dhe_psk_identity{
			       identity =  ClientPSKIdentity,
			       dh_public = ClientPublicDhKey},
			    #state{negotiated_version = Version,
				   diffie_hellman_params = #'DHParameter'{prime = P,
									  base = G},
				   diffie_hellman_keys = {_, ServerDhPrivateKey}} = State0) ->
    case dhe_psk_master_secret(ClientPSKIdentity, P, G, ClientPublicDhKey, ServerDhPrivateKey, State0) of
	#state{} = State1 ->
	    {Record, State} = next_record(State1),
	    next_state(certify, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end;

certify_client_key_exchange(#client_rsa_psk_identity{
			       identity = PskIdentity,
			       exchange_keys =
				   #encrypted_premaster_secret{premaster_secret= EncPMS}},
			    #state{negotiated_version = Version,
				   private_key = Key} = State0) ->
    PremasterSecret = ssl_handshake:decrypt_premaster_secret(EncPMS, Key),
    case server_rsa_psk_master_secret(PskIdentity, PremasterSecret, State0) of
	#state{} = State1 ->
	    {Record, State} = next_record(State1),
	    next_state(certify, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end;

certify_client_key_exchange(#client_srp_public{srp_a = ClientPublicKey},
			    #state{negotiated_version = Version,
				   srp_params =
				       #srp_user{prime = Prime,
						 verifier = Verifier}
				  } = State0) ->
    case server_srp_master_secret(Verifier, Prime, ClientPublicKey, State0) of
	#state{} = State1 ->
	    {Record, State} = next_record(State1),
	    next_state(certify, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, certify, State0)
    end.

%%--------------------------------------------------------------------
-spec cipher(#hello_request{} | #certificate_verify{} | #finished{} | term(),
	     #state{}) -> gen_fsm_state_return().  
%%--------------------------------------------------------------------
cipher(#hello_request{}, State0) ->
    {Record, State} = next_record(State0),
    next_state(cipher, hello, Record, State);

cipher(#certificate_verify{signature = Signature, hashsign_algorithm = CertHashSign},
       #state{role = server, 
	      public_key_info = PublicKeyInfo,
	      negotiated_version = Version,
	      session = #session{master_secret = MasterSecret},
	      hashsign_algorithm = ConnectionHashSign,
	      tls_handshake_history = Handshake
	     } = State0) -> 
    HashSign = case CertHashSign of
		   {_, _} -> CertHashSign;
		   _      -> ConnectionHashSign
	       end,
    case ssl_handshake:certificate_verify(Signature, PublicKeyInfo,
					  Version, HashSign, MasterSecret, Handshake) of
	valid ->
	    {Record, State} = next_record(State0),
	    next_state(cipher, cipher, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, cipher, State0)
    end;

%% client must send a next protocol message if we are expecting it
cipher(#finished{}, #state{role = server, expecting_next_protocol_negotiation = true,
			   next_protocol = undefined, negotiated_version = Version} = State0) ->
       handle_own_alert(?ALERT_REC(?FATAL,?UNEXPECTED_MESSAGE), Version, cipher, State0);

cipher(#finished{verify_data = Data} = Finished, 
       #state{negotiated_version = Version,
	      host = Host,
	      port = Port,
	      role = Role,
	      session = #session{master_secret = MasterSecret} 
	      = Session0,
		  connection_states = ConnectionStates0,
	      tls_handshake_history = Handshake0} = State0) ->
    State = flight_done(State0),
    case ssl_handshake:verify_connection(Version, Finished, 
					 opposite_role(Role), 
					 get_current_connection_state_prf(ConnectionStates0, read),
					 MasterSecret, Handshake0) of
        verified ->
	    Session = register_session(Role, Host, Port, Session0),
	    cipher_role(Role, Data, Session, State);
        #alert{} = Alert ->
	    handle_own_alert(Alert, Version, cipher, State)
    end;

%% only allowed to send next_protocol message after change cipher spec
%% & before finished message and it is not allowed during renegotiation
cipher(#next_protocol{selected_protocol = SelectedProtocol},
       #state{role = server, expecting_next_protocol_negotiation = true} = State0) ->
    {Record, State} = next_record(State0#state{next_protocol = SelectedProtocol}),
    next_state(cipher, cipher, Record, State);

cipher(timeout, State) ->
    { next_state, cipher, State, hibernate };

cipher(Msg, State) ->
    handle_unexpected_message(Msg, cipher, State).

%%--------------------------------------------------------------------
-spec connection(#hello_request{} | #client_hello{} | term(),
		 #state{}) -> gen_fsm_state_return().  
%%--------------------------------------------------------------------
connection(#hello_request{}, #state{host = Host, port = Port,
				    session = #session{own_certificate = Cert} = Session0,
				    session_cache = Cache, session_cache_cb = CacheCb,
				    ssl_options = SslOpts,
				    connection_states = ConnectionStates0,
				    renegotiation = {Renegotiation, _},
				    client_cookie = Cookie} = State0) ->
    Hello = ssl_handshake:client_hello(Host, Port, Cookie, ConnectionStates0, SslOpts,
				       Cache, CacheCb, Renegotiation, Cert),

    State1 = State0#state{session = Session0#session{session_id = Hello#client_hello.session_id}},
    State2 = send_flight(Hello, waiting, State1),

    {Record, State} = next_record(State2),
    next_state(connection, hello, Record, State);
connection(#client_hello{} = Hello, #state{role = server, allow_renegotiate = true} = State0) ->
    %% Mitigate Computational DoS attack
    %% http://www.educatedguesswork.org/2011/10/ssltls_and_computational_dos.html
    %% http://www.thc.org/thc-ssl-dos/ Rather than disabling client
    %% initiated renegotiation we will disallow many client initiated
    %% renegotiations immediately after each other.
    erlang:send_after(?WAIT_TO_ALLOW_RENEGOTIATION, self(), allow_renegotiate),
    State = start_flight(1, State0),
    hello(Hello, State#state{allow_renegotiate = false});

connection(#client_hello{}, #state{role = server, allow_renegotiate = false,
				   connection_states = ConnectionStates0,
				   socket = Socket, transport_cb = Transport,
				   negotiated_version = Version} = State0) ->
    Alert = ?ALERT_REC(?WARNING, ?NO_RENEGOTIATION),
    {BinMsg, ConnectionStates} =
	encode_alert(Alert, Version, ConnectionStates0),
    Transport:send(Socket, BinMsg),
    next_state_connection(connection, State0#state{connection_states = ConnectionStates});
  
connection(timeout, State) ->
    {next_state, connection, State, hibernate};

connection(Msg, State) ->
    handle_unexpected_message(Msg, connection, State).

%%--------------------------------------------------------------------
%% Description: Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event. Not currently used!
%%--------------------------------------------------------------------
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State, get_timeout(State)}.

%%--------------------------------------------------------------------
%% Description: Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/2,3, this function is called to handle
%% the event.
%%--------------------------------------------------------------------
handle_sync_event({application_data, Data}, From, connection, State) ->
    %% We should look into having a worker process to do this to 
    %% parallize send and receive decoding and not block the receiver
    %% if sending is overloading the socket.
    try
	write_application_data(Data, From, State)
    catch throw:Error ->
	    {reply, Error, connection, State, get_timeout(State)}
    end;
handle_sync_event({application_data, Data}, From, StateName, 
		  #state{send_queue = Queue} = State) ->
    %% In renegotiation priorities handshake, send data when handshake is finished
    {next_state, StateName,
     State#state{send_queue = queue:in({From, Data}, Queue)},
     get_timeout(State)};

handle_sync_event({start, Timeout}, StartFrom, hello, State) ->
    Timer = start_or_recv_cancel_timer(Timeout, StartFrom),
    hello(start, State#state{start_or_recv_from = StartFrom,
			     timer = Timer});

%% The two clauses below could happen if a server upgrades a socket in
%% active mode. Note that in this case we are lucky that
%% controlling_process has been evalueated before receiving handshake
%% messages from client. The server should put the socket in passive
%% mode before telling the client that it is willing to upgrade
%% and before calling ssl:ssl_accept/2. These clauses are 
%% here to make sure it is the users problem and not owers if
%% they upgrade an active socket. 
handle_sync_event({start,_}, _, connection, State) ->
    {reply, connected, connection, State, get_timeout(State)};
handle_sync_event({start,_}, _From, error, {Error, State = #state{}}) ->
    {stop, {shutdown, Error}, {error, Error}, State};

handle_sync_event({start, Timeout}, StartFrom, StateName, State) ->
    Timer = start_or_recv_cancel_timer(Timeout, StartFrom),
    {next_state, StateName, State#state{start_or_recv_from = StartFrom,
					timer = Timer}, get_timeout(State)};

handle_sync_event(close, _, StateName, State) ->
    %% Run terminate before returning
    %% so that the reuseaddr inet-option will work
    %% as intended.
    (catch terminate(user_close, StateName, State)),
    {stop, normal, ok, State#state{terminated = true}};

handle_sync_event({shutdown, How0}, _, StateName,
		  #state{transport_cb = Transport,
			 negotiated_version = Version,
			 connection_states = ConnectionStates,
			 socket = Socket} = State) ->
    case How0 of
	How when How == write; How == both ->	    
	    Alert = ?ALERT_REC(?WARNING, ?CLOSE_NOTIFY),
	    {BinMsg, _} =
		encode_alert(Alert, Version, ConnectionStates),
	    Transport:send(Socket, BinMsg);
	_ ->
	    ok
    end,
    
    case Transport:shutdown(Socket, How0) of
	ok ->
	    {reply, ok, StateName, State, get_timeout(State)};
	Error ->
	    {stop, normal, Error, State}
    end;
    
handle_sync_event({recv, N, Timeout}, RecvFrom, connection = StateName, State0) ->
    Timer = start_or_recv_cancel_timer(Timeout, RecvFrom),
    passive_receive(State0#state{bytes_to_read = N,
				 start_or_recv_from = RecvFrom, timer = Timer}, StateName);

%% Doing renegotiate wait with handling request until renegotiate is
%% finished. Will be handled by next_state_is_connection/2.
handle_sync_event({recv, N, Timeout}, RecvFrom, StateName, State) ->
    Timer = start_or_recv_cancel_timer(Timeout, RecvFrom),
    {next_state, StateName, State#state{bytes_to_read = N, start_or_recv_from = RecvFrom,
					timer = Timer},
     get_timeout(State)};

handle_sync_event({new_user, User}, _From, StateName, 
		  State =#state{user_application = {OldMon, _}}) ->
    NewMon = erlang:monitor(process, User),
    erlang:demonitor(OldMon, [flush]),
    {reply, ok, StateName, State#state{user_application = {NewMon,User}},
     get_timeout(State)};

handle_sync_event({get_opts, OptTags}, _From, StateName,
		  #state{socket = Socket,
			 transport_cb = Transport,
			 socket_options = SockOpts} = State) ->
    OptsReply = get_socket_opts(Transport, Socket, OptTags, SockOpts, []),
    {reply, OptsReply, StateName, State, get_timeout(State)};

handle_sync_event(negotiated_next_protocol, _From, StateName, #state{next_protocol = undefined} = State) ->
    {reply, {error, next_protocol_not_negotiated}, StateName, State, get_timeout(State)};
handle_sync_event(negotiated_next_protocol, _From, StateName, #state{next_protocol = NextProtocol} = State) ->
    {reply, {ok, NextProtocol}, StateName, State, get_timeout(State)};

handle_sync_event({set_opts, Opts0}, _From, StateName, 
		  #state{socket_options = Opts1, 
			 socket = Socket,
			 transport_cb = Transport,
			 user_data_buffer = Buffer} = State0) ->
    {Reply, Opts} = set_socket_opts(Transport, Socket, Opts0, Opts1, []),
    State1 = State0#state{socket_options = Opts},
    if 
	Opts#socket_options.active =:= false ->
	    {reply, Reply, StateName, State1, get_timeout(State1)};
	Buffer =:= <<>>, Opts1#socket_options.active =:= false ->
            %% Need data, set active once
	    {Record, State2} = next_record_if_active(State1),
	    case next_state(StateName, StateName, Record, State2) of
		{next_state, StateName, State, Timeout} ->
		    {reply, Reply, StateName, State, Timeout};
		{stop, Reason, State} ->
		    {stop, Reason, State}
	    end;
	Buffer =:= <<>> ->
            %% Active once already set 
	    {reply, Reply, StateName, State1, get_timeout(State1)};
	true ->
	    case read_application_data(<<>>, State1) of
		Stop = {stop,_,_} ->
		    Stop;
		{Record, State2} ->
		    case next_state(StateName, StateName, Record, State2) of
			{next_state, StateName, State, Timeout} ->
			    {reply, Reply, StateName, State, Timeout};
			{stop, Reason, State} ->
			    {stop, Reason, State}
		    end
	    end
    end;

handle_sync_event(renegotiate, From, connection, State) ->
    renegotiate(State#state{renegotiation = {true, From}});

handle_sync_event(renegotiate, _, StateName, State) ->
    {reply, {error, already_renegotiating}, StateName, State, get_timeout(State)};

handle_sync_event({prf, Secret, Label, Seed, WantedLength}, _, StateName,
		  #state{connection_states = ConnectionStates,
			 negotiated_version = Version} = State) ->
    ConnectionState =
	ssl_record:current_connection_state(ConnectionStates, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{master_secret = MasterSecret,
			 client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Reply = try
		SecretToUse = case Secret of
				  _ when is_binary(Secret) -> Secret;
				  master_secret -> MasterSecret
			      end,
		SeedToUse = lists:reverse(
			      lists:foldl(fun(X, Acc) when is_binary(X) -> [X|Acc];
					     (client_random, Acc) -> [ClientRandom|Acc];
					     (server_random, Acc) -> [ServerRandom|Acc]
					  end, [], Seed)),
		ssl_handshake:prf(Version, SecretToUse, Label, SeedToUse, WantedLength)
	    catch
		exit:_ -> {error, badarg};
		error:Reason -> {error, Reason}
	    end,
    {reply, Reply, StateName, State, get_timeout(State)};

handle_sync_event(info, _, StateName, 
		  #state{negotiated_version = Version,
			 session = #session{cipher_suite = Suite}} = State) ->
    
    AtomVersion = ssl_record:protocol_version(Version),
    {reply, {ok, {AtomVersion, ssl:suite_definition(Suite)}},
     StateName, State, get_timeout(State)};

handle_sync_event(session_info, _, StateName, 
		  #state{session = #session{session_id = Id,
					    cipher_suite = Suite}} = State) ->
    {reply, [{session_id, Id}, 
	     {cipher_suite, ssl:suite_definition(Suite)}],
     StateName, State, get_timeout(State)};

handle_sync_event(peer_certificate, _, StateName, 
		  #state{session = #session{peer_certificate = Cert}} 
		  = State) ->
    {reply, {ok, Cert}, StateName, State, get_timeout(State)}.

%%--------------------------------------------------------------------
%% Description: This function is called by a gen_fsm when it receives any
%% other message than a synchronous or asynchronous event
%% (or a system message).
%%--------------------------------------------------------------------

%% raw data from TCP, unpack records
handle_info({Protocol, _, Data}, StateName,
            #state{data_tag = Protocol} = State0) ->
    case next_tls_record(Data, State0) of
	{Record, State} ->
	    next_state(StateName, StateName, Record, State);
	#alert{} = Alert ->
	    handle_normal_shutdown(Alert, StateName, State0), 
	    {stop, {shutdown, own_alert}, State0}
    end;

handle_info({CloseTag, Socket}, StateName,
            #state{socket = Socket, close_tag = CloseTag,
		   negotiated_version = Version} = State) ->
    %% Note that as of TLS 1.1,
    %% failure to properly close a connection no longer requires that a
    %% session not be resumed.  This is a change from TLS 1.0 to conform
    %% with widespread implementation practice.
    case Version of
	{1, N} when N >= 1 ->
	    ok;
	_ ->
	    %% As invalidate_sessions here causes performance issues,
	    %% we will conform to the widespread implementation
	    %% practice and go aginst the spec
	    %%invalidate_session(Role, Host, Port, Session)
	    ok
    end,
    handle_normal_shutdown(?ALERT_REC(?FATAL, ?CLOSE_NOTIFY), StateName, State),
    {stop, {shutdown, transport_closed}, State};

handle_info({ErrorTag, Socket, econnaborted}, StateName,  
	    #state{socket = Socket, transport_cb = Transport,
		   start_or_recv_from = StartFrom, role = Role,
		   error_tag = ErrorTag} = State0)  when StateName =/= connection ->
    State = cancel_dtls_retransmit_timer(State0),
    alert_user(Transport, Socket, StartFrom, ?ALERT_REC(?FATAL, ?CLOSE_NOTIFY), Role),
    {stop, normal, State};

handle_info({ErrorTag, Socket, Reason}, StateName, #state{socket = Socket,
							  error_tag = ErrorTag} = State)  ->
    Report = io_lib:format("SSL: Socket error: ~p ~n", [Reason]),
    error_logger:info_report(Report),
    handle_normal_shutdown(?ALERT_REC(?FATAL, ?CLOSE_NOTIFY), StateName, State),
    {stop, normal, State};

handle_info({'DOWN', MonitorRef, _, _, _}, _, 
	    State0 = #state{user_application={MonitorRef,_Pid}}) ->
    State = cancel_dtls_retransmit_timer(State0),
    {stop, normal, State};

handle_info({timeout, _, dtls_retransmit}, StateName, State0) ->
    State = resend_flight(State0),
    {next_state, StateName, State, get_timeout(State)};

handle_info({timeout, _, msl_timeout}, StateName,
	    State0 = #state{connection_states = ConnectionStates0}) ->
    ConnectionStates = ssl_record:clear_previous_epoch(ConnectionStates0),
    {next_state, StateName, State0#state{connection_states = ConnectionStates,
					 msl_timer = undefined}, get_timeout(State0)};

handle_info(allow_renegotiate, StateName, State) ->
    {next_state, StateName, State#state{allow_renegotiate = true}, get_timeout(State)};

handle_info({cancel_start_or_recv, StartFrom}, StateName,
	    #state{renegotiation = {false, first}} = State) when StateName =/= connection ->
    gen_fsm:reply(StartFrom, {error, timeout}),
    {stop, {shutdown, user_timeout}, State#state{timer = undefined}};

handle_info({cancel_start_or_recv, RecvFrom}, StateName, #state{start_or_recv_from = RecvFrom} = State) ->
    gen_fsm:reply(RecvFrom, {error, timeout}),
    {next_state, StateName, State#state{start_or_recv_from = undefined,
					bytes_to_read = undefined,
					timer = undefined}, get_timeout(State)};

handle_info({cancel_start_or_recv, _RecvFrom}, StateName, State) ->
    {next_state, StateName, State#state{timer = undefined}, get_timeout(State)};

handle_info(Msg, StateName,
	    #state{transport_cb = gen_tcp} = State) ->
    Report = io_lib:format("SSL: Got unexpected info: ~p ~n", [Msg]),
    error_logger:info_report(Report),
    {next_state, StateName, State, get_timeout(State)};

handle_info(Msg, StateName,
            #state{socket = Socket, transport_cb = Transport} = State) ->
    case Transport:handle_ssl_info(Socket, Msg) of
	{next, NextMsg} ->
	    handle_info(NextMsg, StateName, State);
	_ ->
	    Report = io_lib:format("SSL: Got unexpected info: ~p ~n", [Msg]),
	    error_logger:info_report(Report),
	    {next_state, StateName, State, get_timeout(State)}
    end.

%%--------------------------------------------------------------------
%% Description:This function is called by a gen_fsm when it is about
%% to terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%--------------------------------------------------------------------
terminate(_, _, #state{terminated = true}) ->
    %% Happens when user closes the connection using ssl:close/1
    %% we want to guarantee that Transport:close has been called
    %% when ssl:close/1 returns.
    ok;

terminate({shutdown, transport_closed}, StateName, #state{send_queue = SendQueue,
							  renegotiation = Renegotiate} = State) ->
    handle_unrecv_data(StateName, State),
    handle_trusted_certs_db(State),
    notify_senders(SendQueue),
    notify_renegotiater(Renegotiate);

terminate({shutdown, own_alert}, _StateName, #state{send_queue = SendQueue,
				      renegotiation = Renegotiate} = State) ->
    handle_trusted_certs_db(State),
    notify_senders(SendQueue),
    notify_renegotiater(Renegotiate);

terminate(Reason, connection, #state{negotiated_version = Version,
				      connection_states = ConnectionStates,
				      transport_cb = Transport,
				      socket = Socket, send_queue = SendQueue,
				      renegotiation = Renegotiate} = State) ->
    handle_trusted_certs_db(State),
    notify_senders(SendQueue),
    notify_renegotiater(Renegotiate),
    BinAlert = terminate_alert(Reason, Version, ConnectionStates),
    Transport:send(Socket, BinAlert),
    workaround_transport_delivery_problems(Socket, Transport);

terminate(_Reason, _StateName, #state{transport_cb = Transport,
				      socket = Socket, send_queue = SendQueue,
				      renegotiation = Renegotiate} = State) ->
    handle_trusted_certs_db(State),
    notify_senders(SendQueue),
    notify_renegotiater(Renegotiate),
    Transport:close(Socket).

%%--------------------------------------------------------------------
%% code_change(OldVsn, StateName, State, Extra) -> {ok, StateName, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
start_fsm(Role, Host, Port, Socket, {#ssl_options{erl_dist = false},_} = Opts,
	  User, {CbModule, _,_, _} = CbInfo, 
	  Timeout) -> 
    try 
	{ok, Pid} = ssl_connection_sup:start_child([Role, Host, Port, Socket, 
						    Opts, User, CbInfo]), 
	{ok, SslSocket} = socket_control(Socket, Pid, CbModule),
	ok = handshake(SslSocket, Timeout),
	{ok, SslSocket} 
    catch
	error:{badmatch, {error, _} = Error} ->
	    Error
    end;

start_fsm(Role, Host, Port, Socket, {#ssl_options{erl_dist = true},_} = Opts,
	  User, {CbModule, _,_, _} = CbInfo, 
	  Timeout) -> 
    try 
	{ok, Pid} = ssl_connection_sup:start_child_dist([Role, Host, Port, Socket, 
							 Opts, User, CbInfo]), 
	{ok, SslSocket} = socket_control(Socket, Pid, CbModule),
	ok = handshake(SslSocket, Timeout),
	{ok, SslSocket} 
    catch
	error:{badmatch, {error, _} = Error} ->
	    Error
    end.

ssl_init(SslOpts, Role) ->
    
    init_manager_name(SslOpts#ssl_options.erl_dist),

    {ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, OwnCert} = init_certificates(SslOpts, Role),
    PrivateKey =
	init_private_key(PemCacheHandle, SslOpts#ssl_options.key, SslOpts#ssl_options.keyfile,
			 SslOpts#ssl_options.password, Role),
    DHParams = init_diffie_hellman(PemCacheHandle, SslOpts#ssl_options.dh, SslOpts#ssl_options.dhfile, Role),
    {ok, CertDbRef, CertDbHandle, FileRefHandle, CacheHandle, OwnCert, PrivateKey, DHParams}.

init_manager_name(false) ->
    put(ssl_manager, ssl_manager);
init_manager_name(true) ->
    put(ssl_manager, ssl_manager_dist).

init_certificates(#ssl_options{cacerts = CaCerts,
			       cacertfile = CACertFile,
			       certfile = CertFile,
			       cert = Cert}, Role) ->
    {ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle} =
	try 
	    Certs = case CaCerts of
			undefined ->
			    CACertFile;
			_ ->
			    {der, CaCerts}
		    end,
	    {ok, _, _, _, _, _} = ssl_manager:connection_init(Certs, Role)
	catch
	    _:Reason ->
		file_error(CACertFile, {cacertfile, Reason})
	end,
    init_certificates(Cert, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, CertFile, Role).

init_certificates(undefined, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, <<>>, _) ->
    {ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, undefined};

init_certificates(undefined, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, CertFile, client) ->
    try 
	%% Ignoring potential proxy-certificates see: 
	%% http://dev.globus.org/wiki/Security/ProxyFileFormat
	[OwnCert|_] = ssl_certificate:file_to_certificats(CertFile, PemCacheHandle),
	{ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, OwnCert}
    catch _Error:_Reason  ->
	    {ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheHandle, undefined}
    end;

init_certificates(undefined, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheRef, CertFile, server) ->
    try
	[OwnCert|_] = ssl_certificate:file_to_certificats(CertFile, PemCacheHandle),
	{ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheRef, OwnCert}
    catch
	_:Reason ->
	    file_error(CertFile, {certfile, Reason})	    
    end;
init_certificates(Cert, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheRef, _, _) ->
    {ok, CertDbRef, CertDbHandle, FileRefHandle, PemCacheHandle, CacheRef, Cert}.

init_private_key(_, undefined, <<>>, _Password, _Client) ->
    undefined;
init_private_key(DbHandle, undefined, KeyFile, Password, _) ->
    try
	{ok, List} = ssl_manager:cache_pem_file(KeyFile, DbHandle),
	[PemEntry] = [PemEntry || PemEntry = {PKey, _ , _} <- List,
				  PKey =:= 'RSAPrivateKey' orelse
				      PKey =:= 'DSAPrivateKey' orelse
				      PKey =:= 'ECPrivateKey' orelse
				      PKey =:= 'PrivateKeyInfo'
		     ],
	private_key(public_key:pem_entry_decode(PemEntry, Password))
    catch 
	_:Reason ->
	    file_error(KeyFile, {keyfile, Reason}) 
    end;

%% First two clauses are for backwards compatibility
init_private_key(_,{rsa, PrivateKey}, _, _,_) ->
    init_private_key('RSAPrivateKey', PrivateKey);
init_private_key(_,{dsa, PrivateKey},_,_,_) ->
    init_private_key('DSAPrivateKey', PrivateKey);
init_private_key(_,{ec, PrivateKey},_,_,_) ->
    init_private_key('ECPrivateKey', PrivateKey);
init_private_key(_,{Asn1Type, PrivateKey},_,_,_) ->
    private_key(init_private_key(Asn1Type, PrivateKey)).

init_private_key(Asn1Type, PrivateKey) ->
    public_key:der_decode(Asn1Type, PrivateKey).

private_key(#'PrivateKeyInfo'{privateKeyAlgorithm =
				 #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm = ?'rsaEncryption'},
			     privateKey = Key}) ->
    public_key:der_decode('RSAPrivateKey', iolist_to_binary(Key));

private_key(#'PrivateKeyInfo'{privateKeyAlgorithm =
				 #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm = ?'id-dsa'},
			     privateKey = Key}) ->
    public_key:der_decode('DSAPrivateKey', iolist_to_binary(Key));

private_key(Key) ->
    Key.

-spec(file_error(_,_) -> no_return()).
file_error(File, Throw) ->
    case Throw of
	{Opt,{badmatch, {error, {badmatch, Error}}}} ->
	    throw({options, {Opt, binary_to_list(File), Error}});
	_ ->
	    throw(Throw)
    end.

init_diffie_hellman(_,Params, _,_) when is_binary(Params)->
    public_key:der_decode('DHParameter', Params);
init_diffie_hellman(_,_,_, client) ->
    undefined;
init_diffie_hellman(_,_,undefined, _) ->
    ?DEFAULT_DIFFIE_HELLMAN_PARAMS;
init_diffie_hellman(DbHandle,_, DHParamFile, server) ->
    try
	{ok, List} = ssl_manager:cache_pem_file(DHParamFile,DbHandle),
	case [Entry || Entry = {'DHParameter', _ , _} <- List] of
	    [Entry] ->
		public_key:pem_entry_decode(Entry);
	    [] ->
		?DEFAULT_DIFFIE_HELLMAN_PARAMS
	end
    catch
	_:Reason ->
	    file_error(DHParamFile, {dhfile, Reason}) 
    end.

sync_send_all_state_event(FsmPid, Event) ->
    try gen_fsm:sync_send_all_state_event(FsmPid, Event, infinity)
    catch
 	exit:{noproc, _} ->
 	    {error, closed};
	exit:{normal, _} ->
	    {error, closed};
	exit:{{shutdown, _},_} ->
	    {error, closed}
    end.

%% We do currently not support cipher suites that use fixed DH.
%% If we want to implement that we should add a code
%% here to extract DH parameters form cert.
handle_peer_cert(PeerCert, PublicKeyInfo, 
		 #state{session = Session} = State0) ->
    State1 = State0#state{session = 
			 Session#session{peer_certificate = PeerCert},
			 public_key_info = PublicKeyInfo},
    State2 = case PublicKeyInfo of
		 {?'id-ecPublicKey',  #'ECPoint'{point = _ECPoint} = PublicKey, PublicKeyParams} ->
		     ECDHKey = public_key:generate_key(PublicKeyParams),
		     State3 = State1#state{diffie_hellman_keys = ECDHKey},
		     ec_dh_master_secret(ECDHKey, PublicKey, State3);

		 _ -> State1
	     end,
    {Record, State} = next_record(State2),
    next_state(certify, certify, Record, State).

certify_client(#state{client_certificate_requested = true, role = client,
		      cert_db = CertDbHandle,
                      cert_db_ref = CertDbRef,
		      session = #session{own_certificate = OwnCert}} = State) ->
    Certificate = ssl_handshake:certificate(OwnCert, CertDbHandle, CertDbRef, client),
    buffer_flight(Certificate, State);

certify_client(#state{client_certificate_requested = false} = State) ->
    State.

verify_client_cert(#state{client_certificate_requested = true, role = client,
			  negotiated_version = Version,
			  private_key = PrivateKey,
			  session = #session{master_secret = MasterSecret,
					     own_certificate = OwnCert},
			  hashsign_algorithm = HashSign,
			  tls_handshake_history = Handshake0} = State) ->

    %%TODO: for TLS 1.2 we can choose a different/stronger HashSign combination for this.
    case ssl_handshake:client_certificate_verify(OwnCert, MasterSecret, 
						 Version, HashSign, PrivateKey, Handshake0) of
        #certificate_verify{} = Verified ->
	    buffer_flight(Verified, State);
	ignore ->
	    State;
	#alert{} = Alert ->
	    throw(Alert)	    
    end;
verify_client_cert(#state{client_certificate_requested = false} = State) ->
    State.

do_server_hello(Type, NextProtocolsToSend,
		EcPointFormats, EllipticCurves,
		#state{negotiated_version = Version,
		       session = #session{session_id = SessId},
		       connection_states = ConnectionStates0,
		       renegotiation = {Renegotiation, _}}
		= State0) when is_atom(Type) ->

    ServerHello = 
        ssl_handshake:server_hello(SessId, Version, 
                                   ConnectionStates0, Renegotiation,
				   NextProtocolsToSend, EcPointFormats, EllipticCurves),
    State = server_hello(ServerHello,
			 State0#state{expecting_next_protocol_negotiation =
					  NextProtocolsToSend =/= undefined}),
    case Type of	
	new ->
	    new_server_hello(ServerHello, State);
	resumed ->
	    resumed_server_hello(State)
    end.

new_server_hello(#server_hello{cipher_suite = CipherSuite,
			      compression_method = Compression,
			      session_id = SessionId}, 
		#state{session = Session0,
		       negotiated_version = Version} = State0) ->
    try server_certify_and_key_exchange(State0) of 
        #state{} = State1 ->
            State2 = server_hello_done(State1),
	    Session = 
		Session0#session{session_id = SessionId,
				 cipher_suite = CipherSuite,
				 compression_method = Compression},
	    {Record, State} = next_record(State2#state{session = Session}),
	    next_state(hello, certify, Record, State)
    catch        
        #alert{} = Alert ->  
	    handle_own_alert(Alert, Version, hello, State0)
    end.

resumed_server_hello(#state{session = Session,
			    connection_states = ConnectionStates0,
			    negotiated_version = Version} = State0) ->

    case ssl_handshake:master_secret(Version, Session,
				     ConnectionStates0, server) of
	{_, ConnectionStates1} ->
	    State1 = State0#state{connection_states = ConnectionStates1,
				  session = Session},
	    State2 = finalize_handshake(State1, abbreviated, waiting),
	    State3 = expect_cipher_state_change(State2),
	    {Record, State} = next_record(State3),
	    next_state(hello, abbreviated, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, hello, State0)
    end.

handle_new_session(NewId, CipherSuite, Compression, #state{session = Session0} = State0) ->
    Session = Session0#session{session_id = NewId,
			       cipher_suite = CipherSuite,
			       compression_method = Compression}, 
    {Record, State} = next_record(State0#state{session = Session}),
    next_state(hello, certify, Record, State).

handle_resumed_session(SessId, #state{connection_states = ConnectionStates0,
				      negotiated_version = Version,
				      host = Host, port = Port,
				      session_cache = Cache,
				      session_cache_cb = CacheCb} = State0) ->
    Session = CacheCb:lookup(Cache, {{Host, Port}, SessId}),
    case ssl_handshake:master_secret(Version, Session, 
				     ConnectionStates0, client) of
	{_, ConnectionStates} ->
	    State1 = expect_cipher_state_change(State0),
	    {Record, State} = 
		next_record(State1#state{
			      connection_states = ConnectionStates,
			      session = Session}),
	    next_state(hello, abbreviated, Record, State);
	#alert{} = Alert ->
	    handle_own_alert(Alert, Version, hello, State0)
    end.


client_certify_and_key_exchange(#state{negotiated_version = Version} = 
				State0) ->
    try do_client_certify_and_key_exchange(State0) of 
        State1 = #state{} ->
	    State2 = finalize_handshake(State1, certify, waiting),
	    State3 = expect_cipher_state_change(
		       State2#state{
			 %% Reinitialize
			 client_certificate_requested = false}),
	    {Record, State} = next_record(State3),
	    next_state(certify, cipher, Record, State)
    catch        
        throw:#alert{} = Alert ->  
	    handle_own_alert(Alert, Version, certify, State0)
    end.

do_client_certify_and_key_exchange(State0) ->
    State1 = certify_client(State0), 
    State2 = key_exchange(State1),
    verify_client_cert(State2).

server_certify_and_key_exchange(State0) ->
    State1 = certify_server(State0), 
    State2 = key_exchange(State1),
    request_client_cert(State2).
    
server_hello(ServerHello, #state{negotiated_version = Version} = State) ->
    CipherSuite = ServerHello#server_hello.cipher_suite,
    {KeyAlgorithm, _, _, _} = ssl_cipher:suite_definition(CipherSuite),

    State1 = buffer_flight(ServerHello, State),
    State1#state{key_algorithm = KeyAlgorithm,
		 hashsign_algorithm = default_hashsign(Version, KeyAlgorithm)}.

server_hello_done(#state{} = State) ->
    HelloDone = ssl_handshake:server_hello_done(),
    send_flight(HelloDone, waiting, State).

certify_server(#state{key_algorithm = Algo} = State)
  when Algo == dh_anon; Algo == ecdh_anon;
       Algo == psk; Algo == ecdhe_psk; Algo == dhe_psk;
       Algo == srp_anon ->
    State;

certify_server(#state{cert_db = CertDbHandle,
		      cert_db_ref = CertDbRef,
		      session = #session{own_certificate = OwnCert}} = State) ->
    case ssl_handshake:certificate(OwnCert, CertDbHandle, CertDbRef, server) of
	CertMsg = #certificate{} ->
	    buffer_flight(CertMsg, State);
	Alert = #alert{} ->
	    throw(Alert)
    end.

key_exchange(#state{role = server, key_algorithm = rsa} = State) ->
    State;
key_exchange(#state{role = server, key_algorithm = Algo,
		    hashsign_algorithm = HashSignAlgo,
		    diffie_hellman_params = #'DHParameter'{} = Params,
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
		    negotiated_version = Version
		   } = State) 
  when Algo == dhe_dss;
       Algo == dhe_rsa;
       Algo == dh_anon ->
    DHKeys = public_key:generate_key(Params),
    ConnectionState = 
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams, 
    Msg =  ssl_handshake:key_exchange(server, Version, {dh, DHKeys, Params,
					       HashSignAlgo, ClientRandom,
					       ServerRandom,
					       PrivateKey}),
    State1 = buffer_flight(Msg, State),
    State1#state{diffie_hellman_keys = DHKeys};

key_exchange(#state{role = server, private_key = Key, key_algorithm = Algo} = State)
  when Algo == ecdh_ecdsa; Algo == ecdh_rsa ->
    State#state{diffie_hellman_keys = Key};
key_exchange(#state{role = server, key_algorithm = Algo,
		    hashsign_algorithm = HashSignAlgo,
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
		    negotiated_version = Version
		   } = State)
  when Algo == ecdhe_ecdsa; Algo == ecdhe_rsa;
       Algo == ecdh_anon ->

    ECDHKeys = public_key:generate_key(select_curve(State)),
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Msg =  ssl_handshake:key_exchange(server, Version, {ecdh, ECDHKeys,
							HashSignAlgo, ClientRandom,
							ServerRandom,
							PrivateKey}),
    State1 = buffer_flight(Msg, State),
    State1#state{diffie_hellman_keys = ECDHKeys};

key_exchange(#state{role = server, key_algorithm = psk,
		    ssl_options = #ssl_options{psk_identity = undefined}} = State) ->
    State;
key_exchange(#state{role = server, key_algorithm = psk,
		    ssl_options = #ssl_options{psk_identity = PskIdentityHint},
		    hashsign_algorithm = HashSignAlgo,
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
		    negotiated_version = Version
		   } = State) ->
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Msg =  ssl_handshake:key_exchange(server, Version, {psk, PskIdentityHint,
					       HashSignAlgo, ClientRandom,
					       ServerRandom,
					       PrivateKey}),
    buffer_flight(Msg, State);

key_exchange(#state{role = server, key_algorithm = ecdhe_psk,
		    ssl_options = #ssl_options{psk_identity = PskIdentityHint},
		    hashsign_algorithm = HashSignAlgo,
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
		    negotiated_version = Version
		   } = State) ->
    ECDHKeys = public_key:generate_key(select_curve(State)),
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Msg =  ssl_handshake:key_exchange(server, Version, {ecdhe_psk, PskIdentityHint, ECDHKeys,
					       HashSignAlgo, ClientRandom,
					       ServerRandom,
					       PrivateKey}),
    State1 = buffer_flight(Msg, State),
    State1#state{diffie_hellman_keys = ECDHKeys};

key_exchange(#state{role = server, key_algorithm = dhe_psk,
		    ssl_options = #ssl_options{psk_identity = PskIdentityHint},
		    hashsign_algorithm = HashSignAlgo,
		    diffie_hellman_params = #'DHParameter'{} = Params,
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
		    negotiated_version = Version
		   } = State) ->
    DHKeys = public_key:generate_key(Params),
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Msg =  ssl_handshake:key_exchange(server, Version, {dhe_psk, PskIdentityHint, DHKeys, Params,
					       HashSignAlgo, ClientRandom,
					       ServerRandom,
					       PrivateKey}),
    State1 = buffer_flight(Msg, State),
    State1#state{diffie_hellman_keys = DHKeys};

key_exchange(#state{role = server, key_algorithm = rsa_psk,
		    ssl_options = #ssl_options{psk_identity = undefined}} = State) ->
    State;
key_exchange(#state{role = server, key_algorithm = rsa_psk,
		    ssl_options = #ssl_options{psk_identity = PskIdentityHint},
		    hashsign_algorithm = HashSignAlgo,
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
		    negotiated_version = Version
		   } = State) ->
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Msg =  ssl_handshake:key_exchange(server, Version, {psk, PskIdentityHint,
					       HashSignAlgo, ClientRandom,
					       ServerRandom,
					       PrivateKey}),
    buffer_flight(Msg, State);

key_exchange(#state{role = server, key_algorithm = Algo,
		    ssl_options = #ssl_options{user_lookup_fun = LookupFun},
		    hashsign_algorithm = HashSignAlgo,
		    session = #session{srp_username = Username},
		    private_key = PrivateKey,
		    connection_states = ConnectionStates0,
		    negotiated_version = Version
		   } = State)
  when Algo == srp_dss;
       Algo == srp_rsa;
       Algo == srp_anon ->
    SrpParams = handle_srp_identity(Username, LookupFun),
    Keys = case generate_srp_server_keys(SrpParams, 0) of
	       Alert = #alert{} ->
		   throw(Alert);
	       Keys0 = {_,_} ->
		   Keys0
	   end,
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates0, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams,
    Msg =  ssl_handshake:key_exchange(server, Version, {srp, Keys, SrpParams,
					       HashSignAlgo, ClientRandom,
					       ServerRandom,
					       PrivateKey}),
    State1 = buffer_flight(Msg, State),
    State1#state{srp_params = SrpParams,
		 srp_keys = Keys};

key_exchange(#state{role = client, 
		    key_algorithm = rsa,
		    public_key_info = PublicKeyInfo,
		    negotiated_version = Version,
		    premaster_secret = PremasterSecret} = State) ->
    Msg = rsa_key_exchange(Version, PremasterSecret, PublicKeyInfo),
    buffer_flight(Msg, State);

key_exchange(#state{role = client, 
		    key_algorithm = Algorithm,
		    negotiated_version = Version,
		    diffie_hellman_keys = {DhPubKey, _}} = State)
  when Algorithm == dhe_dss;
       Algorithm == dhe_rsa;
       Algorithm == dh_anon ->
    Msg =  ssl_handshake:key_exchange(client, Version, {dh, DhPubKey}),
    buffer_flight(Msg, State);

key_exchange(#state{role = client,
		    key_algorithm = Algorithm,
		    negotiated_version = Version,
		    diffie_hellman_keys = Keys} = State)
  when Algorithm == ecdhe_ecdsa; Algorithm == ecdhe_rsa;
       Algorithm == ecdh_ecdsa; Algorithm == ecdh_rsa;
       Algorithm == ecdh_anon ->
    Msg = ssl_handshake:key_exchange(client, Version, {ecdh, Keys}),
    buffer_flight(Msg, State);

key_exchange(#state{role = client,
		    ssl_options = SslOpts,
		    key_algorithm = psk,
		    negotiated_version = Version} = State) ->
    Msg =  ssl_handshake:key_exchange(client, Version, {psk, SslOpts#ssl_options.psk_identity}),
    buffer_flight(Msg, State);

key_exchange(#state{role = client,
		    ssl_options = SslOpts,
		    key_algorithm = ecdhe_psk,
		    negotiated_version = Version,
		    diffie_hellman_keys = Keys} = State) ->
    Msg =  ssl_handshake:key_exchange(client, Version, {ecdhe_psk, SslOpts#ssl_options.psk_identity, Keys}),
    buffer_flight(Msg, State);

key_exchange(#state{role = client,
		    ssl_options = SslOpts,
		    key_algorithm = dhe_psk,
		    negotiated_version = Version,
		    diffie_hellman_keys = {DhPubKey, _}} = State) ->
    Msg =  ssl_handshake:key_exchange(client, Version, {dhe_psk, SslOpts#ssl_options.psk_identity, DhPubKey}),
    buffer_flight(Msg, State);

key_exchange(#state{role = client,
		    ssl_options = SslOpts,
		    key_algorithm = rsa_psk,
		    public_key_info = PublicKeyInfo,
		    negotiated_version = Version,
		    premaster_secret = PremasterSecret} = State) ->
    Msg = rsa_psk_key_exchange(Version, SslOpts#ssl_options.psk_identity, PremasterSecret, PublicKeyInfo),
    buffer_flight(Msg, State);

key_exchange(#state{role = client,
		    key_algorithm = Algorithm,
		    negotiated_version = Version,
		    srp_keys = {ClientPubKey, _}} = State)
  when Algorithm == srp_dss;
       Algorithm == srp_rsa;
       Algorithm == srp_anon ->
    Msg =  ssl_handshake:key_exchange(client, Version, {srp, ClientPubKey}),
    buffer_flight(Msg, State).

rsa_key_exchange(Version, PremasterSecret, PublicKeyInfo = {Algorithm, _, _})
  when Algorithm == ?rsaEncryption;
       Algorithm == ?md2WithRSAEncryption;
       Algorithm == ?md5WithRSAEncryption;
       Algorithm == ?sha1WithRSAEncryption;
       Algorithm == ?sha224WithRSAEncryption;
       Algorithm == ?sha256WithRSAEncryption;
       Algorithm == ?sha384WithRSAEncryption;
       Algorithm == ?sha512WithRSAEncryption
       ->
    ssl_handshake:key_exchange(client, Version,
			       {premaster_secret, PremasterSecret,
				PublicKeyInfo});
rsa_key_exchange(_, _, _) ->
    throw (?ALERT_REC(?FATAL,?HANDSHAKE_FAILURE)).

rsa_psk_key_exchange(Version, PskIdentity, PremasterSecret, PublicKeyInfo = {Algorithm, _, _})
  when Algorithm == ?rsaEncryption;
       Algorithm == ?md2WithRSAEncryption;
       Algorithm == ?md5WithRSAEncryption;
       Algorithm == ?sha1WithRSAEncryption;
       Algorithm == ?sha224WithRSAEncryption;
       Algorithm == ?sha256WithRSAEncryption;
       Algorithm == ?sha384WithRSAEncryption;
       Algorithm == ?sha512WithRSAEncryption
       ->
    ssl_handshake:key_exchange(client, Version,
			       {psk_premaster_secret, PskIdentity, PremasterSecret,
				PublicKeyInfo});
rsa_psk_key_exchange(_, _, _, _) ->
    throw (?ALERT_REC(?FATAL,?HANDSHAKE_FAILURE)).

request_client_cert(#state{key_algorithm = Alg} = State)
  when Alg == dh_anon; Alg == ecdh_anon;
       Alg == psk; Alg == ecdhe_psk; Alg == dhe_psk; Alg == rsa_psk;
       Alg == srp_dss; Alg == srp_rsa; Alg == srp_anon ->
    State;

request_client_cert(#state{ssl_options = #ssl_options{verify = verify_peer},
			   connection_states = ConnectionStates0,
			   cert_db = CertDbHandle,
			   cert_db_ref = CertDbRef} = State) ->
    Msg = ssl_handshake:certificate_request(ConnectionStates0, CertDbHandle, CertDbRef),
    State1 = buffer_flight(Msg, State),
    State1#state{client_certificate_requested = true};

request_client_cert(#state{ssl_options = #ssl_options{verify = verify_none}} =
		    State) ->
    State.

finalize_handshake(State, StateName, FlightState) ->
    State1 = buffer_flight_change_cipher(#change_cipher_spec{}, State),
    State2 = cipher_protocol_change(State1),
    State3 = next_protocol(State2),
    finished(State, State3, StateName, FlightState).

next_protocol(#state{role = server} = State) ->
    State;
next_protocol(#state{next_protocol = undefined} = State) ->
    State;
next_protocol(#state{expecting_next_protocol_negotiation = false} = State) ->
    State;
next_protocol(#state{next_protocol = NextProtocol} = State) ->
    NextProtocolMessage = ssl_handshake:next_protocol(NextProtocol),
    buffer_flight(NextProtocolMessage, State).

cipher_protocol_change(#state{connection_states = ConnectionStates0} = State) ->
    ConnectionStates =
	ssl_record:activate_pending_connection_state(ConnectionStates0, write),
    State#state{connection_states = ConnectionStates}.

finished(OriginState,
	 #state{role = Role, negotiated_version = Version,
		session = Session,
                connection_states = ConnectionStates0,
                tls_handshake_history = Handshake0} = State, StateName, FlightState) ->
    MasterSecret = Session#session.master_secret,
    Finished = ssl_handshake:finished(Version, Role,
				       get_current_connection_state_prf(ConnectionStates0, write),
				       MasterSecret, Handshake0),
    ConnectionStates1 = save_verify_data(Role, Finished, ConnectionStates0, StateName),
    #state{connection_states = ConnectionStates,
	   tls_handshake_history = Handshake,
	   flight_state = FlightState,
	   flight_buffer = FlightBuffer,
	   message_sequences = MsgSequences,
	   last_read_seq = LastReadSeq,
	   dtls_retransmit_timer = RetransmitTimer,
	   last_retransmit = LastRetransmit} =
	send_flight(Finished, FlightState, State#state{connection_states = ConnectionStates1}),

    OriginState#state{tls_handshake_history = Handshake,
		      flight_state = FlightState,
		      flight_buffer = FlightBuffer,
		      message_sequences = MsgSequences,
		      last_read_seq = LastReadSeq,
		      dtls_retransmit_timer = RetransmitTimer,
		      last_retransmit = LastRetransmit,
		      connection_states = ConnectionStates}.

save_verify_data(client, #finished{verify_data = Data}, ConnectionStates, certify) ->
    ssl_record:set_client_verify_data(current_write, Data, ConnectionStates);
save_verify_data(server, #finished{verify_data = Data}, ConnectionStates, cipher) ->
    ssl_record:set_server_verify_data(current_both, Data, ConnectionStates);
save_verify_data(client, #finished{verify_data = Data}, ConnectionStates, abbreviated) ->
    ssl_record:set_client_verify_data(current_both, Data, ConnectionStates);
save_verify_data(server, #finished{verify_data = Data}, ConnectionStates, abbreviated) ->
    ssl_record:set_server_verify_data(current_write, Data, ConnectionStates).

handle_server_key(#server_key_exchange{exchange_keys = Keys},
		  #state{key_algorithm = KeyAlg,
			 negotiated_version = Version} = State) ->
    Params = ssl_handshake:decode_server_key(Keys, KeyAlg, Version),
    HashSign = connection_hashsign(Params#server_key_params.hashsign, State),
    case HashSign of
	{_, SignAlgo} when SignAlgo == anon; SignAlgo == ecdh_anon ->
	    server_master_secret(Params#server_key_params.params, State);
	_ ->
	    verify_server_key(Params, HashSign, State)
    end.

verify_server_key(#server_key_params{params = Params,
				     params_bin = EncParams,
				     signature = Signature},
		  HashSign = {HashAlgo, _},
		  #state{negotiated_version = Version,
			 public_key_info = PubKeyInfo,
			 connection_states = ConnectionStates} = State) ->
    ConnectionState =
	ssl_record:pending_connection_state(ConnectionStates, read),
    SecParams = ConnectionState#connection_state.security_parameters,
    #security_parameters{client_random = ClientRandom,
			 server_random = ServerRandom} = SecParams, 
    Hash = ssl_handshake:server_key_exchange_hash(HashAlgo,
						  <<ClientRandom/binary,
						    ServerRandom/binary,
						    EncParams/binary>>),
    case ssl_handshake:verify_signature(Version, Hash, HashSign, Signature, PubKeyInfo) of
	true ->
	    server_master_secret(Params, State);
	false ->
	    ?ALERT_REC(?FATAL, ?DECRYPT_ERROR)
    end.

server_master_secret(#server_dh_params{dh_p = P, dh_g = G, dh_y = ServerPublicDhKey},
		     State) ->
    dh_master_secret(P, G, ServerPublicDhKey, undefined, State);

server_master_secret(#server_ecdh_params{curve = ECCurve, public = ECServerPubKey},
		     State) ->
    ECDHKeys = public_key:generate_key(ECCurve),
    ec_dh_master_secret(ECDHKeys, #'ECPoint'{point = ECServerPubKey}, State#state{diffie_hellman_keys = ECDHKeys});

server_master_secret(#server_psk_params{
			hint = IdentityHint},
		     State) ->
    %% store for later use
    State#state{psk_identity = IdentityHint};

server_master_secret(#server_ecdhe_psk_params{
			hint = IdentityHint,
			dh_params = #server_ecdh_params{curve = ECCurve, public = ECServerPubKey}},
		     State) ->
    ECDHKeys = public_key:generate_key(ECCurve),
    ecdhe_psk_master_secret(IdentityHint, ECDHKeys, #'ECPoint'{point = ECServerPubKey}, State#state{diffie_hellman_keys = ECDHKeys});

server_master_secret(#server_dhe_psk_params{
			hint = IdentityHint,
			dh_params = #server_dh_params{dh_p = P, dh_g = G, dh_y = ServerPublicDhKey}},
		     State) ->
    dhe_psk_master_secret(IdentityHint, P, G, ServerPublicDhKey, undefined, State);

server_master_secret(#server_srp_params{srp_n = N, srp_g = G, srp_s = S, srp_b = B},
		     State) ->
    client_srp_master_secret(G, N, S, B, undefined, State).

master_from_premaster_secret(PremasterSecret,
			     #state{session = Session,
				    negotiated_version = Version, role = Role,
				    connection_states = ConnectionStates0} = State) ->
    case ssl_handshake:master_secret(Version, PremasterSecret,
				     ConnectionStates0, Role) of
	{MasterSecret, ConnectionStates} ->
	    State#state{
	      session =
		  Session#session{master_secret = MasterSecret},
	      connection_states = ConnectionStates};
	#alert{} = Alert ->
	    Alert
    end.

dh_master_secret(#'DHParameter'{} = Params, OtherPublicDhKey, MyPrivateKey, State) ->
    PremasterSecret =
	public_key:compute_key(OtherPublicDhKey, MyPrivateKey, Params),
    master_from_premaster_secret(PremasterSecret, State).

dh_master_secret(Prime, Base, PublicDhKey, undefined, State) ->
    Keys = {_, PrivateDhKey} = crypto:generate_key(dh, [Prime, Base]),
    dh_master_secret(Prime, Base, PublicDhKey, PrivateDhKey, State#state{diffie_hellman_keys = Keys});

dh_master_secret(Prime, Base, PublicDhKey, PrivateDhKey, State) ->
    PremasterSecret =
	crypto:compute_key(dh, PublicDhKey, PrivateDhKey, [Prime, Base]),
    master_from_premaster_secret(PremasterSecret, State).

ec_dh_master_secret(ECDHKeys, ECPoint, State) ->
    PremasterSecret =
	public_key:compute_key(ECPoint, ECDHKeys),
    master_from_premaster_secret(PremasterSecret, State).

handle_psk_identity(_PSKIdentity, LookupFun)
  when LookupFun == undefined ->
    error;
handle_psk_identity(PSKIdentity, {Fun, UserState}) ->
    Fun(psk, PSKIdentity, UserState).

server_psk_master_secret(ClientPSKIdentity,
			 #state{ssl_options = SslOpts} = State) ->
    case handle_psk_identity(ClientPSKIdentity, SslOpts#ssl_options.user_lookup_fun) of
	{ok, PSK} when is_binary(PSK) ->
	    Len = byte_size(PSK),
	    PremasterSecret = <<?UINT16(Len), 0:(Len*8), ?UINT16(Len), PSK/binary>>,
	    master_from_premaster_secret(PremasterSecret, State);
	#alert{} = Alert ->
	    Alert;
	_ ->
	    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER)
    end.

ecdhe_psk_master_secret(PSKIdentity, ECDHKeys, ECPoint,
			#state{ssl_options = SslOpts} = State) ->
    case handle_psk_identity(PSKIdentity, SslOpts#ssl_options.user_lookup_fun) of
	{ok, PSK} when is_binary(PSK) ->
	    ECDHSecret =
		public_key:compute_key(ECPoint, ECDHKeys),
	    ECDHLen = erlang:byte_size(ECDHSecret),
	    Len = erlang:byte_size(PSK),
	    PremasterSecret = <<?UINT16(ECDHLen), ECDHSecret/binary, ?UINT16(Len), PSK/binary>>,
	    master_from_premaster_secret(PremasterSecret, State);
	#alert{} = Alert ->
	    Alert;
	_ ->
	    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER)
    end.

dhe_psk_master_secret(PSKIdentity, Prime, Base, PublicDhKey, undefined, State) ->
    Keys = {_, PrivateDhKey} =
	crypto:generate_key(dh, [Prime, Base]),
    dhe_psk_master_secret(PSKIdentity, Prime, Base, PublicDhKey, PrivateDhKey,
			  State#state{diffie_hellman_keys = Keys});

dhe_psk_master_secret(PSKIdentity, Prime, Base, PublicDhKey, PrivateDhKey,
			     #state{ssl_options = SslOpts} = State) ->
    case handle_psk_identity(PSKIdentity, SslOpts#ssl_options.user_lookup_fun) of
	{ok, PSK} when is_binary(PSK) ->
	    DHSecret =
		crypto:compute_key(dh, PublicDhKey, PrivateDhKey,
				   [Prime, Base]),
	    DHLen = erlang:byte_size(DHSecret),
	    Len = erlang:byte_size(PSK),
	    PremasterSecret = <<?UINT16(DHLen), DHSecret/binary, ?UINT16(Len), PSK/binary>>,
	    master_from_premaster_secret(PremasterSecret, State);
	#alert{} = Alert ->
	    Alert;
	_ ->
	    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER)
    end.

server_rsa_psk_master_secret(PskIdentity, PremasterSecret,
			     #state{ssl_options = SslOpts} = State) ->
    case handle_psk_identity(PskIdentity, SslOpts#ssl_options.user_lookup_fun) of
	{ok, PSK} when is_binary(PSK) ->
	    Len = byte_size(PSK),
	    RealPMS = <<?UINT16(48), PremasterSecret/binary, ?UINT16(Len), PSK/binary>>,
	    master_from_premaster_secret(RealPMS, State);
	#alert{} = Alert ->
	    Alert;
	_ ->
	    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER)
    end.

generate_srp_server_keys(_SrpParams, 10) ->
    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER);
generate_srp_server_keys(SrpParams =
			     #srp_user{generator = Generator, prime = Prime,
				       verifier = Verifier}, N) ->
    case crypto:generate_key(srp, {host, [Verifier, Generator, Prime, '6a']}) of
	error ->
	    generate_srp_server_keys(SrpParams, N+1);
	Keys ->
	    Keys
    end.

generate_srp_client_keys(_Generator, _Prime, 10) ->
    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER);
generate_srp_client_keys(Generator, Prime, N) ->

    case crypto:generate_key(srp, {user, [Generator, Prime, '6a']}) of
	error ->
	    generate_srp_client_keys(Generator, Prime, N+1);
	Keys ->
	    Keys
    end.

handle_srp_identity(Username, {Fun, UserState}) ->
    case Fun(srp, Username, UserState) of
	{ok, {SRPParams, Salt, DerivedKey}}
	  when is_atom(SRPParams), is_binary(Salt), is_binary(DerivedKey) ->
	    {Generator, Prime} = ssl_srp_primes:get_srp_params(SRPParams),
	    Verifier = crypto:mod_pow(Generator, DerivedKey, Prime),
	    #srp_user{generator = Generator, prime = Prime,
		      salt = Salt, verifier = Verifier};
	#alert{} = Alert ->
	    throw(Alert);
	_ ->
	    throw(?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER))
    end.

server_srp_master_secret(Verifier, Prime, ClientPub, State = #state{srp_keys = ServerKeys}) ->
    case crypto:compute_key(srp, ClientPub, ServerKeys, {host, [Verifier, Prime, '6a']}) of
	error ->
	    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER);
	PremasterSecret ->
	    master_from_premaster_secret(PremasterSecret, State)
    end.

client_srp_master_secret(_Generator, _Prime, _Salt, _ServerPub, #alert{} = Alert, _State) ->
    Alert;
client_srp_master_secret(Generator, Prime, Salt, ServerPub, undefined, State) ->
    Keys = generate_srp_client_keys(Generator, Prime, 0),
    client_srp_master_secret(Generator, Prime, Salt, ServerPub, Keys, State#state{srp_keys = Keys});

client_srp_master_secret(Generator, Prime, Salt, ServerPub, ClientKeys,
			 #state{ssl_options = SslOpts} = State) ->
    case ssl_srp_primes:check_srp_params(Generator, Prime) of
	ok ->
	    {Username, Password} = SslOpts#ssl_options.srp_identity,
	    DerivedKey = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, Password])]),
	    case crypto:compute_key(srp, ServerPub, ClientKeys, {user, [DerivedKey, Prime, Generator, '6a']}) of
		error ->
		    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER);
		PremasterSecret ->
		    master_from_premaster_secret(PremasterSecret, State)
	    end;
	_ ->
	    ?ALERT_REC(?FATAL, ?ILLEGAL_PARAMETER)
    end.

cipher_role(client, Data, Session, #state{connection_states = ConnectionStates0} = State0) ->
    ConnectionStates = ssl_record:set_server_verify_data(current_both, Data, ConnectionStates0),
    State = flight_done(State0),
    next_state_connection(cipher, ack_connection(State#state{session = Session,
							     connection_states = ConnectionStates}));
     
cipher_role(server, Data, Session,  #state{connection_states = ConnectionStates0} = State) -> 
    ConnectionStates1 = ssl_record:set_client_verify_data(current_read, Data, ConnectionStates0),
    State1 =
	finalize_handshake(State#state{connection_states = ConnectionStates1,
				       session = Session}, cipher, finished),
    next_state_connection(cipher, ack_connection(State1)).

encode_alert(#alert{} = Alert, Version, ConnectionStates) ->
    {BinMsg, Cs1} = ssl_record:encode_alert_record(Alert, Version, ConnectionStates),
    {[BinMsg], Cs1}.

encode_packet(Data, #socket_options{packet=Packet}) ->
    case Packet of
	1 -> encode_size_packet(Data, 8,  (1 bsl 8) - 1);
	2 -> encode_size_packet(Data, 16, (1 bsl 16) - 1);
	4 -> encode_size_packet(Data, 32, (1 bsl 32) - 1);
	_ -> Data
    end.

encode_size_packet(Bin, Size, Max) ->
    Len = erlang:byte_size(Bin),
    case Len > Max of
	true  -> throw({error, {badarg, {packet_to_large, Len, Max}}});
	false -> <<Len:Size, Bin/binary>>
    end.

decode_alerts(Bin) ->
    decode_alerts(Bin, []).

decode_alerts(<<?BYTE(Level), ?BYTE(Description), Rest/binary>>, Acc) ->
    A = ?ALERT_REC(Level, Description),
    decode_alerts(Rest, [A | Acc]);
decode_alerts(<<>>, Acc) ->
    lists:reverse(Acc, []).

passive_receive(State0 = #state{user_data_buffer = Buffer}, StateName) -> 
    case Buffer of
	<<>> ->
	    {Record, State} = next_record(State0),
	    next_state(StateName, StateName, Record, State);
	_ ->
	    case read_application_data(<<>>, State0) of
		Stop = {stop, _, _} ->
		    Stop;
		{Record, State} ->
		    next_state(StateName, StateName, Record, State)
	    end
    end.

read_application_data(Data, #state{user_application = {_Mon, Pid},
				   socket = Socket,
				   transport_cb = Transport,
				   socket_options = SOpts,
				   bytes_to_read = BytesToRead,
				   start_or_recv_from = RecvFrom,
				   timer = Timer,
				   user_data_buffer = Buffer0} = State0) ->
    Buffer1 = if 
		  Buffer0 =:= <<>> -> Data;
		  Data =:= <<>> -> Buffer0;
		  true -> <<Buffer0/binary, Data/binary>>
	      end,
    case get_data(SOpts, BytesToRead, Buffer1) of
	{ok, ClientData, Buffer} -> % Send data
	    SocketOpt = deliver_app_data(Transport, Socket, SOpts, ClientData, Pid, RecvFrom),
	    cancel_timer(Timer),
	    State = State0#state{user_data_buffer = Buffer,
				 start_or_recv_from = undefined,
				 timer = undefined,
				 bytes_to_read = undefined,
				 socket_options = SocketOpt 
				},
	    if
		SocketOpt#socket_options.active =:= false; Buffer =:= <<>> -> 
		    %% Passive mode, wait for active once or recv
		    %% Active and empty, get more data
		    next_record_if_active(State);
	 	true -> %% We have more data
 		    read_application_data(<<>>, State)
	    end;
	{more, Buffer} -> % no reply, we need more data
	    next_record(State0#state{user_data_buffer = Buffer});
	{passive, Buffer} ->
	    next_record_if_active(State0#state{user_data_buffer = Buffer});
	{error,_Reason} -> %% Invalid packet in packet mode
	    deliver_packet_error(Transport, Socket, SOpts, Buffer1, Pid, RecvFrom),
	    {stop, normal, State0}
    end.

write_application_data(Data0, From, #state{socket = Socket,
					   negotiated_version = Version,
					   transport_cb = Transport,
					   connection_states = ConnectionStates0,
					   send_queue = SendQueue,
					   socket_options = SockOpts,
					   ssl_options = #ssl_options{renegotiate_at = RenegotiateAt}} = State) ->
    Data = encode_packet(Data0, SockOpts),
    
    case time_to_renegotiate(Data, ConnectionStates0, RenegotiateAt) of
	true ->
	    renegotiate(State#state{send_queue = queue:in_r({From, Data}, SendQueue),
				    renegotiation = {true, internal}});
	false ->
	    {Msgs, ConnectionStates} = ssl_record:encode_data(Data, Version, ConnectionStates0),
	    Result = Transport:send(Socket, Msgs),
	    {reply, Result,
	     connection, State#state{connection_states = ConnectionStates}, get_timeout(State)}
    end.

time_to_renegotiate(_Data, #connection_states{current_write = 
						    #connection_state{sequence_number = Num}}, RenegotiateAt) ->
    
    %% We could do test:
    %% is_time_to_renegotiate((erlang:byte_size(_Data) div ?MAX_PLAIN_TEXT_LENGTH) + 1, RenegotiateAt),
    %% but we chose to have a some what lower renegotiateAt and a much cheaper test 
    is_time_to_renegotiate(Num, RenegotiateAt).

is_time_to_renegotiate(N, M) when N < M->
    false;
is_time_to_renegotiate(_,_) ->
    true.

%% Picks ClientData 
get_data(_, _, <<>>) ->
    {more, <<>>};
%% Recv timed out save buffer data until next recv
get_data(#socket_options{active=false}, undefined, Buffer) ->
    {passive, Buffer};
get_data(#socket_options{active=Active, packet=Raw}, BytesToRead, Buffer) 
  when Raw =:= raw; Raw =:= 0 ->   %% Raw Mode
    if 
	Active =/= false orelse BytesToRead =:= 0  ->
	    %% Active true or once, or passive mode recv(0)  
	    {ok, Buffer, <<>>};
	byte_size(Buffer) >= BytesToRead ->  
	    %% Passive Mode, recv(Bytes) 
	    <<Data:BytesToRead/binary, Rest/binary>> = Buffer,
	    {ok, Data, Rest};
	true ->
	    %% Passive Mode not enough data
	    {more, Buffer}
    end;
get_data(#socket_options{packet=Type, packet_size=Size}, _, Buffer) ->
    PacketOpts = [{packet_size, Size}], 
    case decode_packet(Type, Buffer, PacketOpts) of
	{more, _} ->
	    {more, Buffer};
	Decoded ->
	    Decoded
    end.

decode_packet({http, headers}, Buffer, PacketOpts) ->
    decode_packet(httph, Buffer, PacketOpts);
decode_packet({http_bin, headers}, Buffer, PacketOpts) ->
    decode_packet(httph_bin, Buffer, PacketOpts);
decode_packet(Type, Buffer, PacketOpts) ->
    erlang:decode_packet(Type, Buffer, PacketOpts).

%% Just like with gen_tcp sockets, an ssl socket that has been configured with
%% {packet, http} (or {packet, http_bin}) will automatically switch to expect
%% HTTP headers after it sees a HTTP Request or HTTP Response line. We
%% represent the current state as follows:
%%    #socket_options.packet =:= http: Expect a HTTP Request/Response line
%%    #socket_options.packet =:= {http, headers}: Expect HTTP Headers
%% Note that if the user has explicitly configured the socket to expect
%% HTTP headers using the {packet, httph} option, we don't do any automatic
%% switching of states.
deliver_app_data(Transport, Socket, SOpts = #socket_options{active=Active, packet=Type},
		 Data, Pid, From) ->
    send_or_reply(Active, Pid, From, format_reply(Transport, Socket, SOpts, Data)),
    SO = case Data of
	     {P, _, _, _} when ((P =:= http_request) or (P =:= http_response)),
			       ((Type =:= http) or (Type =:= http_bin)) ->
	         SOpts#socket_options{packet={Type, headers}};
	     http_eoh when tuple_size(Type) =:= 2 ->
                 % End of headers - expect another Request/Response line
	         {Type1, headers} = Type,
	         SOpts#socket_options{packet=Type1};
	     _ ->
	         SOpts
	 end,
    case Active of
        once ->
            SO#socket_options{active=false};
	_ ->
	    SO
    end.

format_reply(_, _,#socket_options{active = false, mode = Mode, packet = Packet,
			     header = Header}, Data) ->
    {ok, do_format_reply(Mode, Packet, Header, Data)};
format_reply(Transport, Socket, #socket_options{active = _, mode = Mode, packet = Packet,
						header = Header}, Data) ->
    {ssl, ssl_socket:socket(self(), Transport, Socket), do_format_reply(Mode, Packet, Header, Data)}.

deliver_packet_error(Transport, Socket, SO= #socket_options{active = Active}, Data, Pid, From) ->
    send_or_reply(Active, Pid, From, format_packet_error(Transport, Socket, SO, Data)).

format_packet_error(_, _,#socket_options{active = false, mode = Mode}, Data) ->
    {error, {invalid_packet, do_format_reply(Mode, raw, 0, Data)}};
format_packet_error(Transport, Socket, #socket_options{active = _, mode = Mode}, Data) ->
    {ssl_error, ssl_socket:socket(self(), Transport, Socket), {invalid_packet, do_format_reply(Mode, raw, 0, Data)}}.

do_format_reply(binary, _, N, Data) when N > 0 ->  % Header mode
    header(N, Data);
do_format_reply(binary, _, _, Data) ->
    Data;
do_format_reply(list, Packet, _, Data)
  when Packet == http; Packet == {http, headers};
       Packet == http_bin; Packet == {http_bin, headers};
       Packet == httph; Packet == httph_bin ->
    Data;
do_format_reply(list, _,_, Data) ->
    binary_to_list(Data).

header(0, <<>>) ->
    [];
header(_, <<>>) ->
    [];
header(0, Binary) ->
    Binary;
header(N, Binary) ->
    <<?BYTE(ByteN), NewBinary/binary>> = Binary,
    [ByteN | header(N-1, NewBinary)].

send_or_reply(false, _Pid, From, Data) when From =/= undefined ->
    gen_fsm:reply(From, Data);
%% Can happen when handling own alert or tcp error/close and there is
%% no outstanding gen_fsm sync events
send_or_reply(false, no_pid, _, _) ->
    ok;
send_or_reply(_, Pid, _From, Data) ->
    send_user(Pid, Data).

opposite_role(client) ->
    server;
opposite_role(server) ->
    client.

send_user(Pid, Msg) ->
    Pid ! Msg.

handle_tls_handshake(_Handle, StateName, #state{tls_packets = []} = State0) ->
    {Record, State} = next_record(State0),
    next_state(StateName, StateName, Record, State);

handle_tls_handshake(_Handle, StateName, #state{tls_packets = [retransmit],
						last_retransmit = Last} = State0) ->

    Timestamp = timestamp(),
    State2 = if
		 %% TODO: resend window timeout should retransmistion timeout div 2
		 (Last + 500) < Timestamp ->
		     resend_flight(State0#state{tls_packets = []});
		 true ->
		     rearm_dtls_retransmit_timer(State0#state{tls_packets = []})
	     end,
    {Record, State} = next_record(State2),
    next_state(StateName, StateName, Record, State);

handle_tls_handshake(Handle, StateName, #state{tls_packets = [Packet]} = State) ->
    FsmReturn = {next_state, StateName, State#state{tls_packets = []}},
    Handle(Packet, FsmReturn);

handle_tls_handshake(Handle, StateName, #state{tls_packets = [Packet | Packets]} = State0) ->
    FsmReturn = {next_state, StateName, State0#state{tls_packets = Packets}},
    case Handle(Packet, FsmReturn) of
	{next_state, NextStateName, State, _Timeout} ->
	    handle_tls_handshake(Handle, NextStateName, State);
	{stop, _,_} = Stop ->
	    Stop
    end.

next_state(Current,_, #alert{} = Alert, #state{negotiated_version = Version} = State) ->
    handle_own_alert(Alert, Version, Current, State);

next_state(_,Next, no_record, State) ->
    {next_state, Next, State, get_timeout(State)};

next_state(_,Next, #ssl_tls{type = ?ALERT, fragment = EncAlerts}, State0) ->
    State = cancel_dtls_retransmit_timer(State0),
    Alerts = decode_alerts(EncAlerts),
    handle_alerts(Alerts,  {next_state, Next, State, get_timeout(State)});

next_state(Current, Next, #ssl_tls{type = ?HANDSHAKE} = Record,
	   State0 = #state{negotiated_version = Version}) ->
    Handle = 
   	fun({#hello_request{} = Packet, _}, {next_state, connection = SName, State}) ->
   		%% This message should not be included in handshake
   		%% message hashes. Starts new handshake (renegotiation)
		Hs0 = ssl_handshake:init_handshake_history(),
		State1 = start_flight(1, State#state{tls_handshake_history=Hs0,
						     renegotiation = {true, peer}}),
		?MODULE:SName(Packet, State1);
   	   ({#hello_request{} = Packet, _}, {next_state, SName, State}) ->
   		%% This message should not be included in handshake
   		%% message hashes. Already in negotiation so it will be ignored!
   		?MODULE:SName(Packet, State);
	   ({#client_hello{} = Packet, Raw}, {next_state, connection = SName, State}) ->
		Version = Packet#client_hello.client_version,
		Hs0 = ssl_handshake:init_handshake_history(),
		Hs1 = ssl_handshake:update_handshake_history(Hs0, Raw),
		?MODULE:SName(Packet, State#state{tls_handshake_history=Hs1,
   						  renegotiation = {true, peer}});
	   ({Packet, Raw}, {next_state, SName, State = #state{tls_handshake_history=Hs0}}) ->
		Hs1 = ssl_handshake:update_handshake_history(Hs0, Raw),
		?MODULE:SName(Packet, State#state{tls_handshake_history=Hs1});
   	   (_, StopState) -> StopState
   	end,
    try
	State = get_tls_handshake(Record, State0),
	handle_tls_handshake(Handle, Next, State)
    catch throw:#alert{} = Alert ->
	    handle_own_alert(Alert, Version, Current, State0);
	  _:Error ->
	    exit(Error)
    end;

next_state(_, StateName, #ssl_tls{type = ?APPLICATION_DATA, fragment = Data}, State0) ->
    case read_application_data(Data, State0) of
	Stop = {stop,_,_} ->
   	    Stop;
	{Record, State} ->
   	    next_state(StateName, StateName, Record, State)
    end;

next_state(Current, Next, #ssl_tls{version = {254, _}, epoch = Epoch,
				   type = ?CHANGE_CIPHER_SPEC, fragment = <<1>>} =
          _ChangeCipher,
          #state{change_cipher_spec = {true, _},
		 connection_states = ConnectionStates0,
		 tls_cipher_texts = CipherTexts,
		 tls_cipher_texts_next = CipherTextsNext,
		 dtls_handshake_buffer = HsState} = State0) ->

    case ssl_record:current_connection_state_epoch(ConnectionStates0, read) of
	Epoch ->
	    ConnectionStates1 =
		ssl_record:activate_pending_connection_state(ConnectionStates0, read),
	    State1 = start_msl_timeout(State0),
	    {Record, State} = next_record(State1#state{
					    change_cipher_spec = {false, false},
					    connection_states = ConnectionStates1,
					    last_read_seq = 0,
%% This copies in record that we might not want.....
					    tls_cipher_texts = CipherTexts ++ CipherTextsNext,
					    tls_cipher_texts_next = [],
					    dtls_handshake_buffer = ssl_handshake:dtls_handshake_new_epoch(HsState)});
	_ ->
	    %% this is a retransmit, stay where we are
	    {Record, State} = next_record(State0)
    end,
    next_state(Current, Next, Record, State);

next_state(Current, Next, #ssl_tls{version = {254, _}, epoch = Epoch,
				   type = ?CHANGE_CIPHER_SPEC, fragment = <<1>>} =
	       ChangeCipher, State0 = #state{change_cipher_spec = Ccs,
					     connection_states = ConnectionStates0}) ->

    case ssl_record:current_connection_state_epoch(ConnectionStates0, read) of
	Epoch ->
	    {Record, State} = next_record(State0#state{change_cipher_spec = setelement(2, Ccs, ChangeCipher)}),
	    next_state(Current, Next, Record, State);

	_ ->
	    %% ignore resend ChangeCipherSpec messages
	    {Record, State} = next_record(State0),
	    next_state(Current, Next, Record, State)
    end;

next_state(Current, Next, #ssl_tls{type = ?CHANGE_CIPHER_SPEC, fragment = <<1>>} =
          _ChangeCipher,
          #state{connection_states = ConnectionStates0} = State0) ->

    ConnectionStates1 =
	ssl_record:activate_pending_connection_state(ConnectionStates0, read),
    State1 = start_msl_timeout(State0),
    {Record, State} = next_record(State1#state{
				    connection_states = ConnectionStates1, last_read_seq = 0}),
    next_state(Current, Next, Record, State);
next_state(Current, Next, #ssl_tls{type = _Unknown}, State0) ->
    %% Ignore unknown type 
    {Record, State} = next_record(State0),
    next_state(Current, Next, Record, State).

next_tls_record(Data, #state{tls_record_buffer = Buf0,
		       tls_cipher_texts = CT0} = State0) ->
    case ssl_record:get_tls_records(Data, Buf0) of
	{Records, Buf1} ->
	    CT1 = CT0 ++ Records,
	    next_record(State0#state{tls_record_buffer = Buf1,
				     tls_cipher_texts = CT1});
	#alert{} = Alert ->
	    Alert
    end.

next_record(#state{tls_packets = [], tls_cipher_texts = [],
		   change_cipher_spec = {true, ChangeCipher = #ssl_tls{}}} = State) ->
    {ChangeCipher, State};

next_record(#state{tls_packets = [], tls_cipher_texts = [],
		   socket = Socket, transport_cb = Transport} = State) ->
    ssl_socket:setopts(Transport, Socket, [{active,once}]),
    {no_record, State};
next_record(#state{tls_packets = [], tls_cipher_texts = [CT | Rest],
                   connection_states = ConnStates} = State) ->
    #connection_states{min_read_epoch = MinReadEpoch} = ConnStates,
    #connection_state{epoch = CurrEpoch} = ssl_record:current_connection_state(ConnStates, read),
    next_record(CT, MinReadEpoch, CurrEpoch, State#state{tls_cipher_texts = Rest});

next_record(State) ->
    {no_record, State}.

next_record_if_active(State = 
		      #state{socket_options = 
			     #socket_options{active = false}}) ->    
    {no_record ,State};

next_record_if_active(State) ->
    next_record(State).

next_record(#ssl_tls{version = {254, _}, epoch = CTEpoch},
	    MinReadEpoch, CurrentReadEpoch, State)
  when CTEpoch < MinReadEpoch;
       CTEpoch > CurrentReadEpoch + 1 ->
    %% too old or too new, drop it
    next_record(State);

next_record(#ssl_tls{version = {254, _}, epoch = CTEpoch} = CT,
	    _MinReadEpoch, CurrentReadEpoch, 
	    #state{tls_cipher_texts_next = CipherTextsNext} = State)
  when CTEpoch > CurrentReadEpoch ->
    %% to new, enqueue
    next_record(State#state{tls_cipher_texts_next = CipherTextsNext ++ [CT]});

next_record(#ssl_tls{type = Type, version = {254, _}} = CT,
	    _MinReadEpoch, _CurrentReadEpoch, State)
  when Type == ?APPLICATION_DATA ->
    decode_cipher_text_dtls(CT, State);

next_record(#ssl_tls{type = Type, version = {254, _}, epoch = CTEpoch, sequence = SeqNo} = CT,
	    _MinReadEpoch, CurrentReadEpoch,
	    #state{connection_states = ConnStates0} = State)
  when Type /= ?APPLICATION_DATA, CTEpoch < CurrentReadEpoch ->
    %% handshake record from the previous epoch,
    %% trigger resend if the seq is greater than the last decoded seq...

    case ssl_record:connection_state_by_epoch(ConnStates0, CTEpoch, read) of
	#connection_state{sequence_number = PrevSeqNo}
	  when PrevSeqNo < SeqNo ->
	    case ssl_record:decode_cipher_text(CT, ConnStates0) of
		{_, ConnStates} ->
		    %% TODO (maybe / recheck): TRIGGER resend
		    next_record(State#state{connection_states = ConnStates});
		#alert{} ->
		    %% ignore
		    next_record(State)
	    end;
	_ ->
	    %% already dropped that state
	    next_record(State)
    end;

next_record(#ssl_tls{version = {254, _}} = CT,
	    _MinReadEpoch, _CurrentReadEpoch, State) ->
    decode_cipher_text_dtls(CT, State);

next_record(#ssl_tls{} = CT, _MinReadEpoch, _CurrentReadEpoch,
	    #state{connection_states = ConnStates0} = State) ->
    case ssl_record:decode_cipher_text(CT, ConnStates0) of
	{Plain, ConnStates} ->
	    {Plain, State#state{connection_states = ConnStates}};
	#alert{} = Alert ->
	    {Alert, State}
    end.

decode_cipher_text_dtls(CT, #state{connection_states = ConnStates0} = State) ->
    case ssl_record:decode_cipher_text(CT, ConnStates0) of
	{Plain, ConnStates} ->
	    {Plain, State#state{connection_states = ConnStates}};
	#alert{} ->
	    {<<>>, State}
    end.


next_state_connection(StateName, #state{send_queue = Queue0,
					negotiated_version = Version,
					socket = Socket,
					transport_cb = Transport,
					connection_states = ConnectionStates0
				       } = State) ->     
    %% Send queued up data that was queued while renegotiating
    case queue:out(Queue0) of
	{{value, {From, Data}}, Queue} ->
	    {Msgs, ConnectionStates} = 
		ssl_record:encode_data(Data, Version, ConnectionStates0),
	    Result = Transport:send(Socket, Msgs),
	    gen_fsm:reply(From, Result),
	    next_state_connection(StateName,
				  State#state{connection_states = ConnectionStates,
						      send_queue = Queue});		
	{empty, Queue0} ->
	    next_state_is_connection(StateName, State)
    end.

%% In next_state_is_connection/1: clear tls_handshake,
%% premaster_secret and public_key_info (only needed during handshake)
%% to reduce memory foot print of a connection.
next_state_is_connection(_, State = 
		      #state{start_or_recv_from = RecvFrom,
			     socket_options =
			     #socket_options{active = false}}) when RecvFrom =/= undefined ->
    passive_receive(State#state{premaster_secret = undefined,
				public_key_info = undefined,
				tls_handshake_history = ssl_handshake:init_handshake_history()}, connection);

next_state_is_connection(StateName, State0) ->
    {Record, State} = next_record_if_active(State0),
    next_state(StateName, connection, Record, State#state{premaster_secret = undefined,
							  public_key_info = undefined,
							  tls_handshake_history = ssl_handshake:init_handshake_history()}).

register_session(client, Host, Port, #session{is_resumable = new} = Session0) ->
    Session = Session0#session{is_resumable = true},
    ssl_manager:register_session(Host, Port, Session),
    Session;
register_session(server, _, Port, #session{is_resumable = new} = Session0) ->
    Session = Session0#session{is_resumable = true},
    ssl_manager:register_session(Port, Session),
    Session;
register_session(_, _, _, Session) ->
    Session. %% Already registered

invalidate_session(client, Host, Port, Session) ->
    ssl_manager:invalidate_session(Host, Port, Session);
invalidate_session(server, _, Port, Session) ->
    ssl_manager:invalidate_session(Port, Session).

initial_state(Role, Host, Port, Socket, {SSLOptions, SocketOptions}, User,
	      CbInfo = {CbModule, DataTag, CloseTag, ErrorTag}) ->
    ConnType = connection_type(CbInfo, Socket),
    ConnectionStates = ssl_record:init_connection_states(Role, ConnType),
    
    SessionCacheCb = case application:get_env(ssl, session_cb) of
			 {ok, Cb} when is_atom(Cb) ->
			    Cb;
			 _  ->
			     ssl_session_cache
		     end,
    
    Monitor = erlang:monitor(process, User),

    #state{socket_options = SocketOptions,
	   %% We do not want to save the password in the state so that
	   %% could be written in the clear into error logs.
	   ssl_options = SSLOptions#ssl_options{password = undefined},	   
	   session = #session{is_resumable = new},
	   connection_type = ConnType,
	   transport_cb = CbModule,
	   data_tag = DataTag,
	   close_tag = CloseTag,
	   error_tag = ErrorTag,
	   role = Role,
	   host = Host,
	   port = Port,
	   socket = Socket,
	   connection_states = ConnectionStates,
	   tls_packets = [],
	   tls_handshake_buffer = <<>>,
	   tls_record_buffer = <<>>,
	   tls_cipher_texts = [],
	   tls_cipher_texts_next = [],
	   last_retransmit = 0,
	   last_read_seq = 0,
	   user_application = {Monitor, User},
	   user_data_buffer = <<>>,
	   log_alert = true,
	   session_cache_cb = SessionCacheCb,
	   renegotiation = {false, first},
	   start_or_recv_from = undefined,
	   send_queue = queue:new()
	  }.

get_socket_opts(_,_,[], _, Acc) ->
    {ok, Acc};
get_socket_opts(Transport, Socket, [mode | Tags], SockOpts, Acc) ->
    get_socket_opts(Transport, Socket, Tags, SockOpts, 
		    [{mode, SockOpts#socket_options.mode} | Acc]);
get_socket_opts(Transport, Socket, [packet | Tags], SockOpts, Acc) ->
    case SockOpts#socket_options.packet of
	{Type, headers} ->
	    get_socket_opts(Transport, Socket, Tags, SockOpts, [{packet, Type} | Acc]);
	Type ->
	    get_socket_opts(Transport, Socket, Tags, SockOpts, [{packet, Type} | Acc])
    end;
get_socket_opts(Transport, Socket, [header | Tags], SockOpts, Acc) ->
    get_socket_opts(Transport, Socket, Tags, SockOpts, 
		    [{header, SockOpts#socket_options.header} | Acc]);
get_socket_opts(Transport, Socket, [active | Tags], SockOpts, Acc) ->
    get_socket_opts(Transport, Socket, Tags, SockOpts, 
		    [{active, SockOpts#socket_options.active} | Acc]);
get_socket_opts(Transport, Socket, [Tag | Tags], SockOpts, Acc) ->
    try ssl_socket:getopts(Transport, Socket, [Tag]) of
	{ok, [Opt]} ->
	    get_socket_opts(Transport, Socket, Tags, SockOpts, [Opt | Acc]);
	{error, Error} ->
	    {error, {options, {socket_options, Tag, Error}}}
    catch
	%% So that inet behavior does not crash our process
	_:Error -> {error, {options, {socket_options, Tag, Error}}}
    end;
get_socket_opts(_, _,Opts, _,_) ->
    {error, {options, {socket_options, Opts, function_clause}}}.

set_socket_opts(_,_, [], SockOpts, []) ->
    {ok, SockOpts};
set_socket_opts(Transport, Socket, [], SockOpts, Other) ->
    %% Set non emulated options 
    try ssl_socket:setopts(Transport, Socket, Other) of
	ok ->
	    {ok, SockOpts};
	{error, InetError} ->
	    {{error, {options, {socket_options, Other, InetError}}}, SockOpts}
    catch
	_:Error ->
	    %% So that inet behavior does not crash our process
	    {{error, {options, {socket_options, Other, Error}}}, SockOpts}
    end;

set_socket_opts(Transport,Socket, [{mode, Mode}| Opts], SockOpts, Other) when Mode == list; Mode == binary ->
    set_socket_opts(Transport, Socket, Opts, 
		    SockOpts#socket_options{mode = Mode}, Other);
set_socket_opts(_, _, [{mode, _} = Opt| _], SockOpts, _) ->
    {{error, {options, {socket_options, Opt}}}, SockOpts};
set_socket_opts(Transport,Socket, [{packet, Packet}| Opts], SockOpts, Other) when Packet == raw;
									Packet == 0;
									Packet == 1;
									Packet == 2;
									Packet == 4;
									Packet == asn1;
									Packet == cdr;
									Packet == sunrm;
									Packet == fcgi;
									Packet == tpkt;
									Packet == line;
									Packet == http;
									Packet == httph;
									Packet == http_bin;
									Packet == httph_bin ->
    set_socket_opts(Transport, Socket, Opts, 
		    SockOpts#socket_options{packet = Packet}, Other);
set_socket_opts(_, _, [{packet, _} = Opt| _], SockOpts, _) ->
    {{error, {options, {socket_options, Opt}}}, SockOpts};
set_socket_opts(Transport, Socket, [{header, Header}| Opts], SockOpts, Other) when is_integer(Header) ->
    set_socket_opts(Transport, Socket, Opts, 
		    SockOpts#socket_options{header = Header}, Other);
set_socket_opts(_, _, [{header, _} = Opt| _], SockOpts, _) ->
    {{error,{options, {socket_options, Opt}}}, SockOpts};
set_socket_opts(Transport, Socket, [{active, Active}| Opts], SockOpts, Other) when Active == once;
										   Active == true;
										   Active == false ->
    set_socket_opts(Transport, Socket, Opts, 
		    SockOpts#socket_options{active = Active}, Other);
set_socket_opts(_, _, [{active, _} = Opt| _], SockOpts, _) ->
    {{error, {options, {socket_options, Opt}} }, SockOpts};
set_socket_opts(Transport, Socket, [Opt | Opts], SockOpts, Other) ->
    set_socket_opts(Transport, Socket, Opts, SockOpts, [Opt | Other]).

handle_alerts([], Result) ->
    Result;
handle_alerts(_, {stop, _, _} = Stop) ->
    %% If it is a fatal alert immediately close 
    Stop;
handle_alerts([Alert | Alerts], {next_state, StateName, State, _Timeout}) ->
    handle_alerts(Alerts, handle_alert(Alert, StateName, State)).

handle_alert(#alert{level = ?FATAL} = Alert, StateName,
	     #state{socket = Socket, transport_cb = Transport, 
		    start_or_recv_from = From, host = Host,
		    port = Port, session = Session, user_application = {_Mon, Pid},
		    log_alert = Log, role = Role, socket_options = Opts} = State) ->
    invalidate_session(Role, Host, Port, Session),
    log_alert(Log, StateName, Alert),
    alert_user(Transport, Socket, StateName, Opts, Pid, From, Alert, Role),
    {stop, normal, State};

handle_alert(#alert{level = ?WARNING, description = ?CLOSE_NOTIFY} = Alert, 
	     StateName, State) -> 
    handle_normal_shutdown(Alert, StateName, State),
    {stop, {shutdown, peer_close}, State};

handle_alert(#alert{level = ?WARNING, description = ?NO_RENEGOTIATION} = Alert, StateName, 
	     #state{log_alert = Log, renegotiation = {true, internal}} = State) ->
    log_alert(Log, StateName, Alert),
    handle_normal_shutdown(Alert, StateName, State),
    {stop, {shutdown, peer_close}, State};

handle_alert(#alert{level = ?WARNING, description = ?NO_RENEGOTIATION} = Alert, StateName, 
	     #state{log_alert = Log, renegotiation = {true, From}} = State0) ->
    log_alert(Log, StateName, Alert),
    gen_fsm:reply(From, {error, renegotiation_rejected}),
    {Record, State} = next_record(State0),
    next_state(StateName, connection, Record, State);

handle_alert(#alert{level = ?WARNING, description = ?USER_CANCELED} = Alert, StateName, 
	     #state{log_alert = Log} = State0) ->
    log_alert(Log, StateName, Alert),
    {Record, State} = next_record(State0),
    next_state(StateName, StateName, Record, State).

alert_user(Transport, Socket, connection, Opts, Pid, From, Alert, Role) ->
    alert_user(Transport,Socket, Opts#socket_options.active, Pid, From, Alert, Role);
alert_user(Transport, Socket,_, _, _, From, Alert, Role) ->
    alert_user(Transport, Socket, From, Alert, Role).

alert_user(Transport, Socket, From, Alert, Role) ->
    alert_user(Transport, Socket, false, no_pid, From, Alert, Role).

alert_user(_,_, false = Active, Pid, From,  Alert, Role) ->
    %% If there is an outstanding ssl_accept | recv
    %% From will be defined and send_or_reply will
    %% send the appropriate error message.
    ReasonCode = ssl_alert:reason_code(Alert, Role),
    send_or_reply(Active, Pid, From, {error, ReasonCode});
alert_user(Transport, Socket, Active, Pid, From, Alert, Role) ->
    case ssl_alert:reason_code(Alert, Role) of
	closed ->
	    send_or_reply(Active, Pid, From,
			  {ssl_closed, ssl_socket:socket(self(), Transport, Socket)});
	ReasonCode ->
	    send_or_reply(Active, Pid, From,
			  {ssl_error, ssl_socket:socket(self(), Transport, Socket), ReasonCode})
    end.

log_alert(true, Info, Alert) ->
    Txt = ssl_alert:alert_txt(Alert),
    error_logger:format("SSL: ~p: ~s\n", [Info, Txt]);
log_alert(false, _, _) ->
    ok.

handle_own_alert(Alert, Version, StateName, 
		 #state{transport_cb = Transport,
			socket = Socket,
			connection_states = ConnectionStates,
			log_alert = Log} = State0) ->
    State = flight_done(State0),
    try %% Try to tell the other side
	{BinMsg, _} =
	encode_alert(Alert, Version, ConnectionStates),
	Transport:send(Socket, BinMsg),
	workaround_transport_delivery_problems(Socket, Transport)
    catch _:_ ->  %% Can crash if we are in a uninitialized state
	    ignore
    end,
    try %% Try to tell the local user
	log_alert(Log, StateName, Alert),
	handle_normal_shutdown(Alert,StateName, State)
    catch _:_ ->
	    ok
    end,
    {stop, {shutdown, own_alert}, State}.

handle_normal_shutdown(Alert, _, #state{socket = Socket,
					transport_cb = Transport,
					start_or_recv_from = StartFrom,
					role = Role, renegotiation = {false, first}} = State) ->
    cancel_dtls_retransmit_timer(State),
    alert_user(Transport, Socket, StartFrom, Alert, Role);

handle_normal_shutdown(Alert, StateName, #state{socket = Socket,
						socket_options = Opts,
						transport_cb = Transport,
						user_application = {_Mon, Pid},
						start_or_recv_from = RecvFrom, role = Role} = State) ->
    cancel_dtls_retransmit_timer(State),
    alert_user(Transport, Socket, StateName, Opts, Pid, RecvFrom, Alert, Role).

handle_unexpected_message(Msg, Info, #state{negotiated_version = Version} = State) ->
    Alert =  ?ALERT_REC(?FATAL,?UNEXPECTED_MESSAGE),
    handle_own_alert(Alert, Version, {Info, Msg}, State).

make_premaster_secret({MajVer, MinVer}, rsa) ->
    Rand = ssl:random_bytes(?NUM_OF_PREMASTERSECRET_BYTES-2),
    <<?BYTE(MajVer), ?BYTE(MinVer), Rand/binary>>;
make_premaster_secret(_, _) ->
    undefined.

ack_connection(#state{renegotiation = {true, Initiater}} = State) 
  when Initiater == internal;
       Initiater == peer ->
    State#state{renegotiation = undefined};
ack_connection(#state{renegotiation = {true, From}} = State) ->    
    gen_fsm:reply(From, ok),
    State#state{renegotiation = undefined};
ack_connection(#state{renegotiation = {false, first}, 
		      start_or_recv_from = StartFrom,
		      timer = Timer} = State) when StartFrom =/= undefined ->
    gen_fsm:reply(StartFrom, connected),
    cancel_timer(Timer),
    State#state{renegotiation = undefined, start_or_recv_from = undefined, timer = undefined};
ack_connection(State) ->
    State.


renegotiate(#state{role = client} = State0) ->
    %% Handle same way as if server requested
    %% the renegotiation
    Hs0 = ssl_handshake:init_handshake_history(),
    State = start_flight(0, State0#state{tls_handshake_history = Hs0}),
    connection(#hello_request{}, State);
renegotiate(#state{role = server} = State0) ->
    Hs0 = ssl_handshake:init_handshake_history(),
    HelloRequest = ssl_handshake:hello_request(),
    State1 = start_flight(0, State0),
    State2 = send_flight(HelloRequest, waiting, State1),
    {Record, State} = next_record(State2#state{tls_handshake_history = Hs0}),
    next_state(connection, hello, Record, State#state{allow_renegotiate = true}).

notify_senders(SendQueue) -> 
    lists:foreach(fun({From, _}) ->
 			  gen_fsm:reply(From, {error, closed})
 		  end, queue:to_list(SendQueue)).

notify_renegotiater({true, From}) when not is_atom(From)  ->
    gen_fsm:reply(From, {error, closed});
notify_renegotiater(_) ->
    ok.

terminate_alert(Reason, Version, ConnectionStates) when Reason == normal;
							Reason == user_close ->
    {BinAlert, _} = encode_alert(?ALERT_REC(?WARNING, ?CLOSE_NOTIFY),
				 Version, ConnectionStates),
    BinAlert;
terminate_alert({shutdown, _}, Version, ConnectionStates) ->
    {BinAlert, _} = encode_alert(?ALERT_REC(?WARNING, ?CLOSE_NOTIFY),
				 Version, ConnectionStates),
    BinAlert;

terminate_alert(_, Version, ConnectionStates) ->
    {BinAlert, _} = encode_alert(?ALERT_REC(?FATAL, ?INTERNAL_ERROR),
				 Version, ConnectionStates),
    BinAlert.

workaround_transport_delivery_problems(Socket, gen_tcp = Transport) ->
    %% Standard trick to try to make sure all
    %% data sent to the tcp port is really delivered to the
    %% peer application before tcp port is closed so that the peer will
    %% get the correct TLS alert message and not only a transport close.
    ssl_socket:setopts(Transport, Socket, [{active, false}]),
    Transport:shutdown(Socket, write),
    %% Will return when other side has closed or after 30 s
    %% e.g. we do not want to hang if something goes wrong
    %% with the network but we want to maximise the odds that
    %% peer application gets all data sent on the tcp connection.
    Transport:recv(Socket, 0, 30000);
workaround_transport_delivery_problems(Socket, Transport) ->
    Transport:close(Socket).

get_timeout(#state{ssl_options=#ssl_options{hibernate_after = undefined}}) ->
    infinity;
get_timeout(#state{ssl_options=#ssl_options{hibernate_after = HibernateAfter}}) ->
    HibernateAfter.

handle_trusted_certs_db(#state{ssl_options = #ssl_options{cacertfile = <<>>}}) ->
    %% No trusted certs specified
    ok;
handle_trusted_certs_db(#state{cert_db_ref = Ref,
			       cert_db = CertDb,
			       ssl_options = #ssl_options{cacertfile = undefined}}) ->
    %% Certs provided as DER directly can not be shared
    %% with other connections and it is safe to delete them when the connection ends.
    ssl_certificate_db:remove_trusted_certs(Ref, CertDb);
handle_trusted_certs_db(#state{file_ref_db = undefined}) ->
    %% Something went wrong early (typically cacertfile does not exist) so there is nothing to handle
    ok;
handle_trusted_certs_db(#state{cert_db_ref = Ref,
			       file_ref_db = RefDb,
			       ssl_options = #ssl_options{cacertfile = File}}) ->
    case ssl_certificate_db:ref_count(Ref, RefDb, -1) of
	0 ->
	    ssl_manager:clean_cert_db(Ref, File);
	_ ->
	    ok
    end.

bump_hs_message_seq(Seqs = #message_sequences{read = SeqNo}, read) ->
    Seqs1 = Seqs#message_sequences{read = SeqNo + 1},
    {Seqs1, SeqNo};
bump_hs_message_seq(Seqs = #message_sequences{write = SeqNo}, write) ->
    Seqs1 = Seqs#message_sequences{write = SeqNo + 1},
    {Seqs1, SeqNo}.

get_current_connection_state_prf(CStates, Direction) ->
	CS = ssl_record:current_connection_state(CStates, Direction),
	CS#connection_state.security_parameters#security_parameters.prf_algorithm.
get_pending_connection_state_prf(CStates, Direction) ->
	CS = ssl_record:pending_connection_state(CStates, Direction),
	CS#connection_state.security_parameters#security_parameters.prf_algorithm.

connection_hashsign(HashSign = {_, _}, _State) ->
    HashSign;
connection_hashsign(_, #state{hashsign_algorithm = HashSign}) ->
    HashSign.

%% RFC 5246, Sect. 7.4.1.4.1.  Signature Algorithms
%% If the client does not send the signature_algorithms extension, the
%% server MUST do the following:
%%
%% -  If the negotiated key exchange algorithm is one of (RSA, DHE_RSA,
%%    DH_RSA, RSA_PSK, ECDH_RSA, ECDHE_RSA), behave as if client had
%%    sent the value {sha1,rsa}.
%%
%% -  If the negotiated key exchange algorithm is one of (DHE_DSS,
%%    DH_DSS), behave as if the client had sent the value {sha1,dsa}.
%%
%% -  If the negotiated key exchange algorithm is one of (ECDH_ECDSA,
%%    ECDHE_ECDSA), behave as if the client had sent value {sha1,ecdsa}.

default_hashsign(_Version = {Major, Minor}, KeyExchange)
  when Major == 3 andalso Minor >= 3 andalso
       (KeyExchange == rsa orelse
	KeyExchange == dhe_rsa orelse
	KeyExchange == dh_rsa orelse
	KeyExchange == ecdhe_rsa orelse
	KeyExchange == srp_rsa) ->
    {sha, rsa};
default_hashsign(_Version, KeyExchange)
  when KeyExchange == rsa;
       KeyExchange == dhe_rsa;
       KeyExchange == dh_rsa;
       KeyExchange == ecdhe_rsa;
       KeyExchange == srp_rsa ->
    {md5sha, rsa};
default_hashsign(_Version, KeyExchange)
  when KeyExchange == ecdhe_ecdsa;
       KeyExchange == ecdh_ecdsa;
       KeyExchange == ecdh_rsa ->
    {sha, ecdsa};
default_hashsign(_Version, KeyExchange)
  when KeyExchange == dhe_dss;
       KeyExchange == dh_dss;
       KeyExchange == srp_dss ->
    {sha, dsa};
default_hashsign(_Version, KeyExchange)
  when KeyExchange == dh_anon;
       KeyExchange == ecdh_anon;
       KeyExchange == psk;
       KeyExchange == ecdhe_psk;
       KeyExchange == dhe_psk;
       KeyExchange == rsa_psk;
       KeyExchange == srp_anon ->
    {null, anon}.

start_or_recv_cancel_timer(infinity, _RecvFrom) ->
    undefined;
start_or_recv_cancel_timer(Timeout, RecvFrom) ->
    erlang:send_after(Timeout, self(), {cancel_start_or_recv, RecvFrom}).

cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    case erlang:cancel_timer(Timer) of
        false ->
            receive {timeout, Timer, _} -> 0
            after 0 -> false
            end;
        RemainingTime ->
            RemainingTime
    end.

handle_unrecv_data(StateName, #state{socket = Socket, transport_cb = Transport} = State) ->
    ssl_socket:setopts(Transport, Socket, [{active, false}]),
    case Transport:recv(Socket, 0, 0) of
	{error, closed} ->
	    ok;
	{ok, Data} ->
	    handle_close_alert(Data, StateName, State)
    end.

handle_close_alert(Data, StateName, State0) ->
    case next_tls_record(Data, State0) of
	{#ssl_tls{type = ?ALERT, fragment = EncAlerts}, State} ->
	    [Alert|_] = decode_alerts(EncAlerts),
	    handle_normal_shutdown(Alert, StateName, State);
	_ ->
	    ok
    end.

select_curve(#state{client_ecc = {[Curve|_], _}}) ->
    {namedCurve, Curve};
select_curve(_) ->
    {namedCurve, ?secp256k1}.

connection_type({gen_tcp, _, _, _}, _) ->
    stream;
connection_type({CbModule, _, _, _}, Socket) ->
    CbModule:connection_type(Socket).

%% flight encapsulates all state changes, commit_flight applies the state changes to main state

buffer_handshake_rec(Rec, State = #state{flight_state = preparing, flight_buffer = Buffer}) ->
    State#state{flight_buffer = queue:in(Rec, Buffer)};
buffer_handshake_rec(Rec, State0) ->
    State = cancel_dtls_retransmit_timer(State0),
    State#state{flight_state = preparing, flight_buffer = queue:from_list([Rec])}.

buffer_flight_change_cipher(#change_cipher_spec{} = HsRec,
			    State = #state{connection_states = ConnectionStates0}) ->
    Epoch = ssl_record:current_connection_state_epoch(ConnectionStates0, write),
    buffer_handshake_rec({Epoch, 0, HsRec}, State).

buffer_flight(HandshakeRec,
	      State0 = #state{message_sequences = MsgSequences0,
			      negotiated_version = Version,
			      connection_states = ConnectionStates0,
			      tls_handshake_history = Handshake0}) ->
    Epoch = ssl_record:current_connection_state_epoch(ConnectionStates0, write),
    {MsgSequences1, MsgSeq} = bump_hs_message_seq(MsgSequences0, write),
    %% TODO: something thats avoid the double encoding would be nice, i.e. encode header and body extra, and have a combinator that does the MTU breakdown...
    {HsHistory, _} = ssl_handshake:encode_handshake(HandshakeRec, Version, MsgSeq, 16*1024*1024),
    Handshake1 = ssl_handshake:update_handshake_history(Handshake0, HsHistory),

    buffer_handshake_rec({Epoch, MsgSeq, HandshakeRec},
			 State0#state{message_sequences = MsgSequences1,
				      tls_handshake_history = Handshake1}).

%% FlightState's:
%%  - waiting:  we expect an answer to this and will retransmit if we don't get it
%%  - finished: we don't expect answer, but will retransmit if we get a retransmit
%%  - done:     we don't expect answer and  will not retransmit if we get a retransmit
%%
start_flight(ReadMsgSeq, #state{role = Role,
				ssl_options = SslOpts,
				connection_states = ConnectionStates} = State) ->
    #connection_state{epoch = Epoch} =
	ssl_record:current_connection_state(ConnectionStates, write),
    if
	Epoch == 0 ->
	    MsgSeq = init_message_sequences(Role, SslOpts);

	true ->
	    MsgSeq = init_message_sequences()
    end,
    State#state{
      message_sequences = MsgSeq,
      dtls_handshake_buffer = ssl_handshake:dtls_handshake_new_flight(ReadMsgSeq)}.

send_flight(HandshakeRec, FlightState, State) ->
    send_flight(FlightState, buffer_flight(HandshakeRec, State)).

send_flight(FlightState, State = #state{negotiated_version = Version,
					flight_buffer = Buffer}) ->

    State1 = do_send_flight(queue:to_list(Buffer), [], State),
    finish_send_flight(Version, FlightState, State1).

resend_flight(State = #state{negotiated_version = Version,
			     flight_state = FlightState,
			     flight_buffer = Buffer})
  when FlightState == finished; FlightState == waiting ->
    State1 = do_send_flight(queue:to_list(Buffer), [], State),
    finish_send_flight(Version, FlightState, State1);

resend_flight(State) ->
    State.

flight_done(State) ->
    cancel_dtls_retransmit_timer(State#state{flight_state = done,
					     flight_buffer = undefined}).

do_send_flight([], BinMsgs, State = #state{transport_cb = Transport, socket = Socket}) ->
    Transport:send(Socket, lists:reverse(BinMsgs)),
    State;
do_send_flight([{Epoch, MsgSeq, HandshakeRec}|T], BinMsgs0,
	       State = #state{negotiated_version = Version,
			      connection_states = ConnectionStates0}) ->
    CS0 = ssl_record:connection_state_by_epoch(ConnectionStates0, Epoch, write),
    {BinMsgs, CS1} = encode_handshake_rec(HandshakeRec, Version, MsgSeq, BinMsgs0, CS0),
    ConnectionStates1 = ssl_record:set_connection_state_by_epoch(ConnectionStates0, CS1, write),
    do_send_flight(T, BinMsgs, State#state{connection_states = ConnectionStates1}).

cancel_dtls_retransmit_timer(State = #state{dtls_retransmit_timer = TimerRef}) ->
    cancel_timer(TimerRef),
    State#state{dtls_retransmit_timer = undefined}.

rearm_dtls_retransmit_timer(State = #state{dtls_retransmit_timer = undefined}) ->
    TimerRef = erlang:start_timer(1000, self(), dtls_retransmit),
    State#state{dtls_retransmit_timer = TimerRef};
rearm_dtls_retransmit_timer(State) ->
    State.

finish_send_flight({254, _}, waiting, State) ->
    TimerRef = erlang:start_timer(1000, self(), dtls_retransmit),
    State#state{
      dtls_retransmit_timer = TimerRef,
      last_retransmit = timestamp(),
      flight_state = waiting};

finish_send_flight(_, FlightState, State) ->
    State#state{flight_state = FlightState}.

encode_handshake_rec(#change_cipher_spec{}, Version, _, BinMsgs0, CS0) ->
    {BinMsg, CS1} = ssl_record:encode_change_cipher_spec(Version, CS0),
    {[BinMsg|BinMsgs0], CS1};
encode_handshake_rec(HandshakeRec, Version, MsgSeq, BinMsgs0, CS0) ->
    {_, Fragments} = ssl_handshake:encode_handshake(HandshakeRec, Version, MsgSeq, 1400),
    lists:foldl(fun(F, {Bin, C0}) ->
			{B, C1} = ssl_record:encode_handshake(F, Version, C0),
			{[B|Bin], C1} end, {BinMsgs0, CS0}, Fragments).

start_msl_timeout(State = #state{msl_timer = OldTimer}) ->
    cancel_timer(OldTimer),
    TimerRef =  erlang:start_timer(2 * 60 * 1000, self(), msl_timeout),
    State#state{msl_timer = TimerRef}.

init_message_sequences() ->
    #message_sequences{read = 0, write = 0}.

init_message_sequences(server, #ssl_options{verify_client_hello = true}) ->
    #message_sequences{read = 0, write = 1};
init_message_sequences(_, _) ->
    #message_sequences{read = 0, write = 1}.

negotiated_version(Version, undefined) ->
    Version;
negotiated_version(_, Version) ->
    Version.

expect_cipher_state_change(#state{change_cipher_spec = Ccs} = State) ->
    State#state{change_cipher_spec = setelement(1, Ccs, true)}.

get_tls_handshake(#ssl_tls{version = {254, _}, sequence = SeqNo},
		  State = #state{last_read_seq = ReadSeqNo})
  when SeqNo < ReadSeqNo ->
    State;

get_tls_handshake(#ssl_tls{version = {254, _}} = Record,
		  State = #state{dtls_handshake_buffer = HsState0}) ->
    case ssl_handshake:get_dtls_handshake(Record, HsState0) of
	{Packets, ReadSeq, HsState} ->
	    State#state{tls_packets = Packets,
			dtls_handshake_buffer = HsState,
			last_read_seq = ReadSeq};
	{retransmit, HsState} ->
	    State#state{tls_packets = [retransmit],
			dtls_handshake_buffer = HsState}
	end;

get_tls_handshake(#ssl_tls{version = RecVersion, fragment = Data},
		  State = #state{tls_handshake_buffer = Buf0,
				 negotiated_version = Version}) ->
    {Packets, Buf} =
	ssl_handshake:get_tls_handshake(negotiated_version(RecVersion,Version),Data,Buf0),
    State#state{tls_packets = Packets, tls_handshake_buffer = Buf}.

timestamp() ->
    {Mega, Sec, Micro} = erlang:now(),
    Mega * 1000000 * 1000 + Sec * 1000 + (Micro div 1000).
