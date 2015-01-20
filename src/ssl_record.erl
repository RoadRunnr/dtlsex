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
%% Purpose: Help functions for handling the SSL-Record protocol 
%% 
%%----------------------------------------------------------------------

-module(ssl_record).

-include("ssl_record.hrl").
-include("ssl_internal.hrl").
-include("ssl_alert.hrl").
-include("ssl_handshake.hrl").
-include("ssl_cipher.hrl").

%% Connection state handling
-export([init_connection_states/2, init_connection_state_seq/2,
         current_connection_state/2, pending_connection_state/2,
	 current_connection_state_epoch/2, clear_previous_epoch/1,
	 connection_state_by_epoch/3, set_connection_state_by_epoch/3,
         update_security_params/3,
         set_mac_secret/4,
	 set_master_secret/2, 
         activate_pending_connection_state/2,
         set_pending_cipher_state/4,
	 set_renegotiation_flag/2,
	 set_client_verify_data/3,
	 set_server_verify_data/3,
	 encode_tls_cipher_text/5]).

%% Handling of incoming data
-export([get_tls_records/2]).

%% Encoding records
-export([encode_handshake/3, encode_alert_record/3,
	 encode_change_cipher_spec/2, encode_data/3]).

%% Decoding
-export([decode_cipher_text/2]).

%% Misc.
-export([protocol_version/1, lowest_protocol_version/2,
	 highest_protocol_version/1, highest_connection_protocol_version/1,
	 supported_protocol_versions/0, supported_protocol_versions/1,
	 is_acceptable_version/1, is_acceptable_version/2]).

-export([compressions/0]).

-compile(inline).

-define(INITIAL_BYTES, 5).

%%====================================================================
%% Internal application API
%%====================================================================

%%--------------------------------------------------------------------
-spec init_connection_states(client | server, stream | datagram) -> #connection_states{}.
%%
%% Description: Creates a connection_states record with appropriate
%% values for the initial SSL connection setup. 
%%--------------------------------------------------------------------
init_connection_states(Role, ConnType) ->
    ConnectionEnd = record_protocol_role(Role),
    Current = initial_connection_state(ConnectionEnd, ConnType),
    Pending = empty_connection_state(ConnectionEnd),
    #connection_states{min_read_epoch = 0,
		       current_read = Current,
		       pending_read = Pending,
		       current_write = Current,
		       pending_write = Pending}.

%%--------------------------------------------------------------------
-spec current_connection_state(#connection_states{}, read | write) ->
				      #connection_state{}.
%%
%% Description: Returns the instance of the connection_state record
%% that is currently defined as the current conection state.
%%--------------------------------------------------------------------  
current_connection_state(#connection_states{current_read = Current},
			 read) ->
    Current;
current_connection_state(#connection_states{current_write = Current},
			 write) ->
    Current.

%%--------------------------------------------------------------------
-spec init_connection_state_seq(tls_version(), #connection_states{}) ->
				       #connection_state{}.
%%
%% Description: Copy the read sequence number to the write sequence number
%% This is only valid for DTLS in the first client_hello
%%--------------------------------------------------------------------
init_connection_state_seq({254, _},
			  #connection_states{
			    current_read = Read = #connection_state{epoch = 0},
			    current_write = Write = #connection_state{epoch = 0}} = CS0) ->
    CS0#connection_states{current_write =
			      Write#connection_state{
				sequence_number = Read#connection_state.sequence_number}};
init_connection_state_seq(_, CS) ->
    CS.

%%--------------------------------------------------------------------
-spec current_connection_state_epoch(#connection_states{}, read | write) ->
					    integer().
%%
%% Description: Returns the epoch the connection_state record
%% that is currently defined as the current conection state.
%%--------------------------------------------------------------------
current_connection_state_epoch(#connection_states{current_read = Current},
			 read) ->
    Current#connection_state.epoch;
current_connection_state_epoch(#connection_states{current_write = Current},
			 write) ->
    Current#connection_state.epoch.

%%--------------------------------------------------------------------
-spec pending_connection_state(#connection_states{}, read | write) ->
				      #connection_state{}.
%%
%% Description: Returns the instance of the connection_state record
%% that is currently defined as the pending conection state.
%%--------------------------------------------------------------------  
pending_connection_state(#connection_states{pending_read = Pending},    
			 read) ->
    Pending;
pending_connection_state(#connection_states{pending_write = Pending},
			 write) ->
    Pending.

%%--------------------------------------------------------------------
-spec connection_state_by_epoch(#connection_states{}, integer(), read | write) ->
				      #connection_state{}.
%%
%% Description: Returns the instance of the connection_state record
%% that is defined by the Epoch.
%%--------------------------------------------------------------------
connection_state_by_epoch(#connection_states{previous_read = CS}, Epoch, read)
  when CS#connection_state.epoch == Epoch ->
    CS;
connection_state_by_epoch(#connection_states{current_read = CS}, Epoch, read)
  when CS#connection_state.epoch == Epoch ->
    CS;
connection_state_by_epoch(#connection_states{pending_read = CS}, Epoch, read)
  when CS#connection_state.epoch == Epoch ->
    CS;
connection_state_by_epoch(#connection_states{previous_write = CS}, Epoch, write)
  when CS#connection_state.epoch == Epoch ->
    CS;
connection_state_by_epoch(#connection_states{current_write = CS}, Epoch, write)
  when CS#connection_state.epoch == Epoch ->
    CS;
connection_state_by_epoch(#connection_states{pending_write = CS}, Epoch, write)
  when CS#connection_state.epoch == Epoch ->
    CS.

%%--------------------------------------------------------------------
-spec set_connection_state_by_epoch(#connection_states{},
				    #connection_state{}, read | write) -> ok.
%%
%% Description: Returns the instance of the connection_state record
%% that is defined by the Epoch.
%%--------------------------------------------------------------------
set_connection_state_by_epoch(ConnectionStates0 =
			      #connection_states{previous_read = CS},
			      NewCS = #connection_state{epoch = Epoch}, read)
  when CS#connection_state.epoch == Epoch ->
    ConnectionStates0#connection_states{previous_read = NewCS};

set_connection_state_by_epoch(ConnectionStates0 =
			      #connection_states{current_read = CS},
			      NewCS = #connection_state{epoch = Epoch}, read)
  when CS#connection_state.epoch == Epoch ->
    ConnectionStates0#connection_states{current_read = NewCS};

set_connection_state_by_epoch(ConnectionStates0 =
			      #connection_states{pending_read = CS},
			      NewCS = #connection_state{epoch = Epoch}, read)
  when CS#connection_state.epoch == Epoch ->
    ConnectionStates0#connection_states{pending_read = NewCS};

set_connection_state_by_epoch(ConnectionStates0 =
			      #connection_states{previous_write = CS},
			      NewCS = #connection_state{epoch = Epoch}, write)
  when CS#connection_state.epoch == Epoch ->
    ConnectionStates0#connection_states{previous_write = NewCS};

set_connection_state_by_epoch(ConnectionStates0 =
			      #connection_states{current_write = CS},
			      NewCS = #connection_state{epoch = Epoch}, write)
  when CS#connection_state.epoch == Epoch ->
    ConnectionStates0#connection_states{current_write = NewCS};

set_connection_state_by_epoch(ConnectionStates0 =
			      #connection_states{pending_write = CS},
			      NewCS = #connection_state{epoch = Epoch}, write)
  when CS#connection_state.epoch == Epoch ->
    ConnectionStates0#connection_states{pending_write = NewCS}.

%%--------------------------------------------------------------------
-spec update_security_params(#security_parameters{}, #security_parameters{},
			     #connection_states{}) -> #connection_states{}.
%%
%% Description: Creates a new instance of the connection_states record
%% where the pending states gets its security parameters updated.
%%--------------------------------------------------------------------  
update_security_params(ReadParams, WriteParams, States = 
		       #connection_states{pending_read = Read,
					  pending_write = Write}) -> 
    States#connection_states{pending_read =
                             Read#connection_state{security_parameters = 
                                                   ReadParams},
                             pending_write = 
                             Write#connection_state{security_parameters = 
                                                    WriteParams}
                            }.
%%--------------------------------------------------------------------
-spec set_mac_secret(binary(), binary(), client | server, 
			#connection_states{}) -> #connection_states{}.			       
%%
%% Description: update the mac_secret field in pending connection states
%%--------------------------------------------------------------------
set_mac_secret(ClientWriteMacSecret, ServerWriteMacSecret, client, States) ->
    set_mac_secret(ServerWriteMacSecret, ClientWriteMacSecret, States);
set_mac_secret(ClientWriteMacSecret, ServerWriteMacSecret, server, States) ->
    set_mac_secret(ClientWriteMacSecret, ServerWriteMacSecret, States).

set_mac_secret(ReadMacSecret, WriteMacSecret,
	       States = #connection_states{pending_read = Read,
					   pending_write = Write}) ->
    States#connection_states{
      pending_read = Read#connection_state{mac_secret = ReadMacSecret},
      pending_write = Write#connection_state{mac_secret = WriteMacSecret}
     }.


%%--------------------------------------------------------------------
-spec set_master_secret(binary(), #connection_states{}) -> #connection_states{}.
%%
%% Description: Set master_secret in pending connection states
%%--------------------------------------------------------------------
set_master_secret(MasterSecret,
                  States = #connection_states{pending_read = Read,
                                              pending_write = Write}) -> 
    ReadSecPar = Read#connection_state.security_parameters,
    Read1 = Read#connection_state{
              security_parameters = ReadSecPar#security_parameters{
                                      master_secret = MasterSecret}},
    WriteSecPar = Write#connection_state.security_parameters,
    Write1 = Write#connection_state{
               security_parameters = WriteSecPar#security_parameters{
                                       master_secret = MasterSecret}},
    States#connection_states{pending_read = Read1, pending_write = Write1}.

%%--------------------------------------------------------------------
-spec set_renegotiation_flag(boolean(), #connection_states{}) -> #connection_states{}.
%%
%% Description: Set secure_renegotiation in pending connection states
%%--------------------------------------------------------------------
set_renegotiation_flag(Flag, #connection_states{
			 current_read = CurrentRead0,
			 current_write = CurrentWrite0,
			 pending_read = PendingRead0,
			 pending_write = PendingWrite0} 
		       = ConnectionStates) ->
    CurrentRead = CurrentRead0#connection_state{secure_renegotiation = Flag},
    CurrentWrite = CurrentWrite0#connection_state{secure_renegotiation = Flag},
    PendingRead = PendingRead0#connection_state{secure_renegotiation = Flag},
    PendingWrite = PendingWrite0#connection_state{secure_renegotiation = Flag},
    ConnectionStates#connection_states{current_read = CurrentRead, 
				       current_write = CurrentWrite, 
				       pending_read = PendingRead, 
				       pending_write = PendingWrite}.

%%--------------------------------------------------------------------
-spec set_client_verify_data(current_read | current_write | current_both,
			     binary(), #connection_states{})->
				    #connection_states{}.
%%
%% Description: Set verify data in connection states.                 
%%--------------------------------------------------------------------
set_client_verify_data(current_read, Data, 
		       #connection_states{current_read = CurrentRead0,
					  pending_write = PendingWrite0} 
		       = ConnectionStates) ->
    CurrentRead = CurrentRead0#connection_state{client_verify_data = Data},
    PendingWrite = PendingWrite0#connection_state{client_verify_data = Data},
    ConnectionStates#connection_states{current_read = CurrentRead,
				       pending_write = PendingWrite};
set_client_verify_data(current_write, Data, 
		       #connection_states{pending_read = PendingRead0,
					  current_write = CurrentWrite0} 
		       = ConnectionStates) ->
    PendingRead = PendingRead0#connection_state{client_verify_data = Data},
    CurrentWrite = CurrentWrite0#connection_state{client_verify_data = Data},
    ConnectionStates#connection_states{pending_read = PendingRead,
				       current_write = CurrentWrite};
set_client_verify_data(current_both, Data, 
		       #connection_states{current_read = CurrentRead0,
					  current_write = CurrentWrite0} 
		       = ConnectionStates) ->
    CurrentRead = CurrentRead0#connection_state{client_verify_data = Data},
    CurrentWrite = CurrentWrite0#connection_state{client_verify_data = Data},
    ConnectionStates#connection_states{current_read = CurrentRead,
				       current_write = CurrentWrite}.
%%--------------------------------------------------------------------
-spec set_server_verify_data(current_read | current_write | current_both,
			     binary(), #connection_states{})->
				    #connection_states{}.
%%
%% Description: Set verify data in pending connection states.
%%--------------------------------------------------------------------
set_server_verify_data(current_write, Data, 
		       #connection_states{pending_read = PendingRead0,
					  current_write = CurrentWrite0} 
		       = ConnectionStates) ->
    PendingRead = PendingRead0#connection_state{server_verify_data = Data},
    CurrentWrite = CurrentWrite0#connection_state{server_verify_data = Data},
    ConnectionStates#connection_states{pending_read = PendingRead,
				       current_write = CurrentWrite};

set_server_verify_data(current_read, Data, 
		       #connection_states{current_read = CurrentRead0,
					  pending_write = PendingWrite0} 
		       = ConnectionStates) ->
    CurrentRead = CurrentRead0#connection_state{server_verify_data = Data},
    PendingWrite = PendingWrite0#connection_state{server_verify_data = Data},
    ConnectionStates#connection_states{current_read = CurrentRead,
				       pending_write = PendingWrite};

set_server_verify_data(current_both, Data, 
		       #connection_states{current_read = CurrentRead0,
					  current_write = CurrentWrite0} 
		       = ConnectionStates) ->
    CurrentRead = CurrentRead0#connection_state{server_verify_data = Data},
    CurrentWrite = CurrentWrite0#connection_state{server_verify_data = Data},
    ConnectionStates#connection_states{current_read = CurrentRead,
				       current_write = CurrentWrite}.

%%--------------------------------------------------------------------
-spec activate_pending_connection_state(#connection_states{}, read | write) ->
					       #connection_states{}.
%%
%% Description: Creates a new instance of the connection_states record
%% where the pending state of <Type> has been activated. 
%%--------------------------------------------------------------------
activate_pending_connection_state(States = 
                                  #connection_states{current_read = Current,
						     pending_read = Pending},
                                  read) ->
    NewCurrent = Pending#connection_state{epoch = connection_state_next_epoch(Current),
					  sequence_number = 0},
    SecParams = Pending#connection_state.security_parameters,
    ConnectionEnd = SecParams#security_parameters.connection_end,
    EmptyPending = empty_connection_state(ConnectionEnd),
    SecureRenegotation = NewCurrent#connection_state.secure_renegotiation,
    NewPending = EmptyPending#connection_state{secure_renegotiation = SecureRenegotation},
    States#connection_states{min_read_epoch = Current#connection_state.epoch,
			     previous_read = Current,
			     current_read = NewCurrent,
                             pending_read = NewPending
                            };

activate_pending_connection_state(States = 
                                  #connection_states{current_write = Current,
						     pending_write = Pending},
                                  write) ->
    NewCurrent = Pending#connection_state{epoch = connection_state_next_epoch(Current),
					  sequence_number = 0},
    SecParams = Pending#connection_state.security_parameters,
    ConnectionEnd = SecParams#security_parameters.connection_end,
    EmptyPending = empty_connection_state(ConnectionEnd),
    SecureRenegotation = NewCurrent#connection_state.secure_renegotiation,
    NewPending = EmptyPending#connection_state{secure_renegotiation = SecureRenegotation},
    States#connection_states{previous_write = Current,
			     current_write = NewCurrent,
                             pending_write = NewPending
                            }.

%%--------------------------------------------------------------------
-spec clear_previous_epoch(#connection_states{}) ->
				  #connection_states{}.
%%
%% Description: Advance to min_read_epoch to the current read epoch.
%%--------------------------------------------------------------------
clear_previous_epoch(States =
			 #connection_states{current_read = Current}) ->
    States#connection_states{min_read_epoch = Current#connection_state.epoch}.

%%--------------------------------------------------------------------
-spec set_pending_cipher_state(#connection_states{}, #cipher_state{},
			       #cipher_state{}, client | server) ->
				      #connection_states{}.
%%
%% Description: Set the cipher state in the specified pending connection state.
%%--------------------------------------------------------------------
set_pending_cipher_state(#connection_states{pending_read = Read,
                                            pending_write = Write} = States,
                         ClientState, ServerState, server) ->
    States#connection_states{
        pending_read = Read#connection_state{cipher_state = ClientState},
        pending_write = Write#connection_state{cipher_state = ServerState}};

set_pending_cipher_state(#connection_states{pending_read = Read,
                                            pending_write = Write} = States,
                         ClientState, ServerState, client) ->
    States#connection_states{
        pending_read = Read#connection_state{cipher_state = ServerState},
        pending_write = Write#connection_state{cipher_state = ClientState}}.

%%--------------------------------------------------------------------
-spec get_tls_records(binary(), binary()) -> {[binary()], binary()} | #alert{}.
%%			     
%% Description: Given old buffer and new data from TCP, packs up a records
%% and returns it as a list of tls_compressed binaries also returns leftover
%% data
%%--------------------------------------------------------------------
get_tls_records(Data, <<>>) ->
    get_tls_records_aux(Data, []);
get_tls_records(Data, Buffer) ->
    get_tls_records_aux(list_to_binary([Buffer, Data]), []).

get_tls_records_aux(<<?BYTE(?APPLICATION_DATA),?BYTE(MajVer),?BYTE(MinVer),
		     ?UINT16(Length), Data:Length/binary, Rest/binary>>, 
		    Acc) when MajVer < 128 ->
    get_tls_records_aux(Rest, [#ssl_tls{type = ?APPLICATION_DATA,
					version = {MajVer, MinVer},
					fragment = Data} | Acc]);
get_tls_records_aux(<<?BYTE(?HANDSHAKE),?BYTE(MajVer),?BYTE(MinVer),
		     ?UINT16(Length), 
		     Data:Length/binary, Rest/binary>>, Acc) when MajVer < 128 ->
    get_tls_records_aux(Rest, [#ssl_tls{type = ?HANDSHAKE,
					version = {MajVer, MinVer},
					fragment = Data} | Acc]);
get_tls_records_aux(<<?BYTE(?ALERT),?BYTE(MajVer),?BYTE(MinVer),
		     ?UINT16(Length), Data:Length/binary, 
		     Rest/binary>>, Acc) when MajVer < 128 ->
    get_tls_records_aux(Rest, [#ssl_tls{type = ?ALERT,
					version = {MajVer, MinVer},
					fragment = Data} | Acc]);
get_tls_records_aux(<<?BYTE(?CHANGE_CIPHER_SPEC),?BYTE(MajVer),?BYTE(MinVer),
		     ?UINT16(Length), Data:Length/binary, Rest/binary>>, 
		    Acc) when MajVer < 128 ->
    get_tls_records_aux(Rest, [#ssl_tls{type = ?CHANGE_CIPHER_SPEC,
					version = {MajVer, MinVer},
					fragment = Data} | Acc]);

get_tls_records_aux(<<?BYTE(?APPLICATION_DATA),?BYTE(MajVer),?BYTE(MinVer),
		      ?UINT16(Epoch), ?UINT48(SequenceNumber),
		      ?UINT16(Length), Data:Length/binary, Rest/binary>>,
		    Acc) when MajVer >= 128 ->
    get_tls_records_aux(Rest, [#ssl_tls{type = ?APPLICATION_DATA,
					version = {MajVer, MinVer},
					epoch = Epoch, sequence = SequenceNumber,
					fragment = Data} | Acc]);
get_tls_records_aux(<<?BYTE(?HANDSHAKE),?BYTE(MajVer),?BYTE(MinVer),
		      ?UINT16(Epoch), ?UINT48(SequenceNumber),
		      ?UINT16(Length),
		      Data:Length/binary, Rest/binary>>, Acc) when MajVer >= 128 ->
    get_tls_records_aux(Rest, [#ssl_tls{type = ?HANDSHAKE,
					version = {MajVer, MinVer},
					epoch = Epoch, sequence = SequenceNumber,
					fragment = Data} | Acc]);
get_tls_records_aux(<<?BYTE(?ALERT),?BYTE(MajVer),?BYTE(MinVer),
		      ?UINT16(Epoch), ?UINT48(SequenceNumber),
		      ?UINT16(Length), Data:Length/binary,
		      Rest/binary>>, Acc) when MajVer >= 128 ->
    get_tls_records_aux(Rest, [#ssl_tls{type = ?ALERT,
					version = {MajVer, MinVer},
					epoch = Epoch, sequence = SequenceNumber,
					fragment = Data} | Acc]);
get_tls_records_aux(<<?BYTE(?CHANGE_CIPHER_SPEC),?BYTE(MajVer),?BYTE(MinVer),
		      ?UINT16(Epoch), ?UINT48(SequenceNumber),
		      ?UINT16(Length), Data:Length/binary, Rest/binary>>,
		    Acc) when MajVer >= 128 ->
    get_tls_records_aux(Rest, [#ssl_tls{type = ?CHANGE_CIPHER_SPEC,
					version = {MajVer, MinVer},
					epoch = Epoch, sequence = SequenceNumber,
					fragment = Data} | Acc]);


%% Matches an ssl v2 client hello message.
%% The server must be able to receive such messages, from clients that
%% are willing to use ssl v3 or higher, but have ssl v2 compatibility.
get_tls_records_aux(<<1:1, Length0:15, Data0:Length0/binary, Rest/binary>>,
		    Acc) ->
    case Data0 of
	<<?BYTE(?CLIENT_HELLO), ?BYTE(MajVer), ?BYTE(MinVer), _/binary>> ->
	    Length = Length0-1,
	    <<?BYTE(_), Data1:Length/binary>> = Data0,
	    Data = <<?BYTE(?CLIENT_HELLO), ?UINT24(Length), Data1/binary>>,
	    get_tls_records_aux(Rest, [#ssl_tls{type = ?HANDSHAKE,
						version = {MajVer, MinVer},
						fragment = Data} | Acc]);
	_ ->
	    ?ALERT_REC(?FATAL, ?HANDSHAKE_FAILURE)
	    
    end;

get_tls_records_aux(<<0:1, _CT:7, ?BYTE(_MajVer), ?BYTE(_MinVer),
                     ?UINT16(Length), _/binary>>,
                    _Acc) when Length > ?MAX_CIPHER_TEXT_LENGTH ->
    ?ALERT_REC(?FATAL, ?RECORD_OVERFLOW);

get_tls_records_aux(<<1:1, Length0:15, _/binary>>,_Acc) 
  when Length0 > ?MAX_CIPHER_TEXT_LENGTH ->
    ?ALERT_REC(?FATAL, ?RECORD_OVERFLOW);

get_tls_records_aux(Data, Acc) ->
    case size(Data) =< ?MAX_CIPHER_TEXT_LENGTH + ?INITIAL_BYTES of
	true ->
	    {lists:reverse(Acc), Data};
	false ->
	    ?ALERT_REC(?FATAL, ?UNEXPECTED_MESSAGE)
	end.
%%--------------------------------------------------------------------
-spec protocol_version(tls_atom_version() | tls_version()) -> 
			      tls_version() | tls_atom_version().		      
%%     
%% Description: Creates a protocol version record from a version atom
%% or vice versa.
%%--------------------------------------------------------------------
protocol_version('dtlsv1.2') ->
    {254, 253};
protocol_version(dtlsv1) ->
    {254, 255};
protocol_version('tlsv1.2') ->
    {3, 3};
protocol_version('tlsv1.1') ->
    {3, 2};
protocol_version(tlsv1) ->
    {3, 1};
protocol_version(sslv3) ->
    {3, 0};
protocol_version(sslv2) -> %% Backwards compatibility
    {2, 0};
protocol_version({254, 253}) ->
    'dtlsv1.2';
protocol_version({254, 255}) ->
    dtlsv1;
protocol_version({3, 3}) ->
    'tlsv1.2';
protocol_version({3, 2}) ->
    'tlsv1.1';
protocol_version({3, 1}) ->
    tlsv1;
protocol_version({3, 0}) ->
    sslv3.
%%--------------------------------------------------------------------
-spec lowest_protocol_version(tls_version(), tls_version()) -> tls_version().
%%     
%% Description: Lowes protocol version of two given versions 
%%--------------------------------------------------------------------
lowest_protocol_version(Version = {M, N}, {M, O}) when M < 128, N < O ->
    Version;
lowest_protocol_version(Version = {M, N}, {M, O}) when M >= 128, N > O ->
    Version;
lowest_protocol_version({M, _}, 
			Version = {M, _}) ->
    Version;
lowest_protocol_version(Version = {M,_},
			{N, _}) when M < 128, N < 128, M < N ->
    Version;
lowest_protocol_version(Version = {M,_},
			{N, _}) when M >=128, N >= 128, M > N ->
    Version;
lowest_protocol_version(_,Version) ->
    Version.
%%--------------------------------------------------------------------
-spec highest_protocol_version([tls_version()]) -> tls_version().
%%     
%% Description: Highest protocol version present in a list
%%--------------------------------------------------------------------
highest_protocol_version([Ver | Vers]) ->
    highest_protocol_version(Ver, Vers).

highest_protocol_version(Version, []) ->
    Version;
highest_protocol_version(Version = {N, M}, [{N, O} | Rest])   when N < 128, M > O ->
    highest_protocol_version(Version, Rest);
highest_protocol_version(Version = {N, M}, [{N, O} | Rest])   when N >= 128, M < O ->
    highest_protocol_version(Version, Rest);
highest_protocol_version({M, _}, [Version = {M, _} | Rest]) ->
    highest_protocol_version(Version, Rest);
highest_protocol_version(Version = {M,_}, [{N,_} | Rest])  when M < 128, N < 128, M > N ->
    highest_protocol_version(Version, Rest);
highest_protocol_version(Version = {M,_}, [{N,_} | Rest])  when M >= 128, N >= 128, M < N ->
    highest_protocol_version(Version, Rest);
highest_protocol_version(_, [Version | Rest]) ->
    highest_protocol_version(Version, Rest).

%%--------------------------------------------------------------------
-spec highest_connection_protocol_version(stream | datagram) -> tls_version().
%%
%% Description: Highest protocol version for the connection
%%--------------------------------------------------------------------
highest_connection_protocol_version(ConnType) ->
    highest_protocol_version(supported_protocol_versions(ConnType)).

%%--------------------------------------------------------------------
-spec supported_protocol_versions() -> [tls_version()].					 
%%
%% Description: Protocol versions supported
%%--------------------------------------------------------------------
supported_protocol_versions() ->
    supported_protocol_versions(stream).

supported_protocol_versions(ConnType) ->
    Fun = fun(Version) ->
		  protocol_version(Version) 
	  end,
    case application:get_env(ssl, protocol_version_atom(ConnType)) of
	undefined ->
	    lists:map(Fun, supported_protocol_versions(ConnType, []));
	{ok, []} ->
	    lists:map(Fun, supported_protocol_versions(ConnType, []));
	{ok, Vsns} when is_list(Vsns) ->
	    Versions = lists:filter(fun is_acceptable_version/1, lists:map(Fun, Vsns)),
	    supported_protocol_versions(ConnType, Versions);
	{ok, Vsn} ->
	    Versions = lists:filter(fun is_acceptable_version/1, [Fun(Vsn)]),
	    supported_protocol_versions(ConnType, Versions)
    end.

supported_protocol_versions(ConnType, []) ->
    Vsns = supported_connection_protocol_versions(ConnType, []),
    application:set_env(ssl, protocol_version_atom(ConnType), Vsns),
    Vsns;

supported_protocol_versions(_Type, [_|_] = Vsns) ->
    Vsns.

supported_connection_protocol_versions(stream, []) ->
    case sufficient_tlsv1_2_crypto_support() of
	true ->
	    ?ALL_STREAM_SUPPORTED_VERSIONS;
	false ->
	    ?MIN_STREAM_SUPPORTED_VERSIONS
    end;

supported_connection_protocol_versions(datagram, []) ->
    case sufficient_tlsv1_2_crypto_support() of
	true ->
	    ?ALL_DATAGRAM_SUPPORTED_VERSIONS;
	false ->
	    ?MIN_DATAGRAM_SUPPORTED_VERSIONS
    end.


%%--------------------------------------------------------------------
-spec is_acceptable_version(tls_version()) -> boolean().
-spec is_acceptable_version(tls_version(), Supported :: [tls_version()]) -> boolean().
%%     
%% Description: ssl version 2 is not acceptable security risks are too big.
%% 
%%--------------------------------------------------------------------
is_acceptable_version({N,_}) 
  when N >= ?LOWEST_MAJOR_SUPPORTED_VERSION ->
    true;
is_acceptable_version(_) ->
    false.

is_acceptable_version({N,_} = Version, Versions)   
  when N >= ?LOWEST_MAJOR_SUPPORTED_VERSION ->
    lists:member(Version, Versions);
is_acceptable_version(_,_) ->
    false.

%%--------------------------------------------------------------------
-spec compressions() -> [binary()].
%%     
%% Description: return a list of compressions supported (currently none)
%%--------------------------------------------------------------------
compressions() ->
    [?byte(?NULL)].

%%--------------------------------------------------------------------
-spec decode_cipher_text(#ssl_tls{}, #connection_states{}) ->
				{#ssl_tls{}, #connection_states{}}| #alert{}.
%%     
%% Description: Decode cipher text
%%--------------------------------------------------------------------
decode_cipher_text(CipherText = #ssl_tls{version = {254, _}},
					 ConnectionStates0) ->
    #ssl_tls{epoch = Epoch, sequence = SeqNo} = CipherText,
    ReadState0 = connection_state_by_epoch(ConnectionStates0, Epoch, read),
    #connection_state{compression_state = CompressionS0,
		      security_parameters = SecParams,
		      sequence_number = ReadSeqNo} = ReadState0,
    CompressAlg = SecParams#security_parameters.compression_algorithm,
   case decipher(CipherText, ReadState0) of
       {Compressed, ReadState1} ->
	   {Plain, CompressionS1} = uncompress(CompressAlg, 
					       Compressed, CompressionS0),
	   ConnectionStates = set_connection_state_by_epoch(
				 ConnectionStates0,
				 ReadState1#connection_state{
				   compression_state = CompressionS1,
				   sequence_number =
				       erlang:max(ReadSeqNo, SeqNo)}, read),
	   {Plain, ConnectionStates};
       #alert{} = Alert ->
	   Alert
   end;

decode_cipher_text(CipherText, ConnnectionStates0) ->
    ReadState0 = ConnnectionStates0#connection_states.current_read,
    #connection_state{compression_state = CompressionS0,
                      security_parameters = SecParams} = ReadState0,
    CompressAlg = SecParams#security_parameters.compression_algorithm,
   case decipher(CipherText, ReadState0) of
       {Compressed, ReadState1} ->
           {Plain, CompressionS1} = uncompress(CompressAlg,
                                               Compressed, CompressionS0),
           ConnnectionStates = ConnnectionStates0#connection_states{
                                 current_read = ReadState1#connection_state{
                                                  compression_state = CompressionS1}},
           {Plain, ConnnectionStates};
       #alert{} = Alert ->
           Alert
   end.
%%--------------------------------------------------------------------
-spec encode_data(binary(), tls_version(), #connection_states{}) ->
			 {iolist(), #connection_states{}}.
%%
%% Description: Encodes data to send on the ssl-socket.
%%--------------------------------------------------------------------
encode_data(Frag, Version,
	    #connection_states{current_write = #connection_state{
				 security_parameters =
				     #security_parameters{bulk_cipher_algorithm = BCA}}} =
		ConnectionStates) ->
    Data = split_bin(Frag, ?MAX_PLAIN_TEXT_LENGTH, Version, BCA),
    encode_iolist(?APPLICATION_DATA, Data, Version, ConnectionStates).

%%--------------------------------------------------------------------
-spec encode_handshake(iolist(), tls_version(), #connection_state{}) ->
			      {iolist(), #connection_state{}}.
%%
%% Description: Encodes a handshake message to send on the ssl-socket.
%%--------------------------------------------------------------------
encode_handshake(Frag, Version, ConnectionState)
  when is_record(ConnectionState, connection_state) ->
    encode_plain_text(?HANDSHAKE, Version, Frag, ConnectionState).

%%--------------------------------------------------------------------
-spec encode_alert_record(#alert{}, tls_version(), #connection_states{}) ->
				 {iolist(), #connection_states{}}.
%%
%% Description: Encodes an alert message to send on the ssl-socket.
%%--------------------------------------------------------------------
encode_alert_record(#alert{level = Level, description = Description},
                    Version, ConnectionStates) ->
    encode_plain_text(?ALERT, Version, <<?BYTE(Level), ?BYTE(Description)>>,
		      ConnectionStates).

%%--------------------------------------------------------------------
-spec encode_change_cipher_spec(tls_version(), #connection_state{}) ->
				       {iolist(), #connection_state{}}.
%%
%% Description: Encodes a change_cipher_spec-message to send on the ssl socket.
%%--------------------------------------------------------------------
encode_change_cipher_spec(Version, ConnectionState)
  when is_record(ConnectionState, connection_state) ->
    encode_plain_text(?CHANGE_CIPHER_SPEC, Version, <<1:8>>, ConnectionState).

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
encode_iolist(Type, Data, Version, ConnectionStates0) ->
    {ConnectionStates, EncodedMsg} =
        lists:foldl(fun(Text, {CS0, Encoded}) ->
			    {Enc, CS1} = encode_plain_text(Type, Version, Text, CS0),
			    {CS1, [Enc | Encoded]}
		    end, {ConnectionStates0, []}, Data),
    {lists:reverse(EncodedMsg), ConnectionStates}.

initial_connection_state(ConnectionEnd, ConnType) ->
    #connection_state{security_parameters =
			  initial_security_params(ConnectionEnd, ConnType),
		      epoch = 0, sequence_number = 0
                     }.

initial_security_params(ConnectionEnd, ConnType) ->
    SecParams = #security_parameters{connection_end = ConnectionEnd,
				     compression_algorithm = ?NULL},
    ssl_cipher:security_parameters(highest_connection_protocol_version(ConnType), ?TLS_NULL_WITH_NULL_NULL,
				   SecParams).

empty_connection_state(ConnectionEnd) ->
    SecParams = empty_security_params(ConnectionEnd),
    #connection_state{security_parameters = SecParams}.

empty_security_params(ConnectionEnd = ?CLIENT) ->
    #security_parameters{connection_end = ConnectionEnd,
                         client_random = random()};
empty_security_params(ConnectionEnd = ?SERVER) ->
    #security_parameters{connection_end = ConnectionEnd,
                         server_random = random()}.
random() ->
    Secs_since_1970 = calendar:datetime_to_gregorian_seconds(
			calendar:universal_time()) - 62167219200,
    Random_28_bytes = crypto:rand_bytes(28),
    <<?UINT32(Secs_since_1970), Random_28_bytes/binary>>.

record_protocol_role(client) ->
    ?CLIENT;
record_protocol_role(server) ->
    ?SERVER.

%% 1/n-1 splitting countermeasure Rizzo/Duong-Beast, RC4 chiphers are not vulnerable to this attack.
split_bin(<<FirstByte:8, Rest/binary>>, ChunkSize, Version, BCA) when BCA =/= ?RC4 andalso ({3, 1} == Version orelse
											    {3, 0} == Version) ->
    do_split_bin(Rest, ChunkSize, [[FirstByte]]);
split_bin(Bin, ChunkSize, _, _) ->
    do_split_bin(Bin, ChunkSize, []).

do_split_bin(<<>>, _, Acc) ->
    lists:reverse(Acc);
do_split_bin(Bin, ChunkSize, Acc) ->
    case Bin of
        <<Chunk:ChunkSize/binary, Rest/binary>> ->
            do_split_bin(Rest, ChunkSize, [Chunk | Acc]);
        _ ->
            lists:reverse(Acc, [Bin])
    end.

encode_plain_text(Type, Version, Data,
		  #connection_state{
			   compression_state=CompS0,
			   epoch=Epoch,
			   sequence_number=Seq,
			   security_parameters=
			       #security_parameters{compression_algorithm=CompAlg}
			  }=CS0) ->
    {Comp, CompS1} = compress(CompAlg, Data, CompS0),
    CS1 = CS0#connection_state{compression_state = CompS1},
    {CipherText, CS2} = cipher(Type, Version, Comp, CS1),
    CTBin = encode_tls_cipher_text(Type, Version, Epoch, Seq, CipherText),
    {CTBin, CS2};

encode_plain_text(Type, Version, Data, ConnectionStates) ->
    #connection_states{current_write=CS0} = ConnectionStates,
    {CTBin, CS1} = encode_plain_text(Type, Version, Data, CS0),
    {CTBin, ConnectionStates#connection_states{current_write = CS1}}.

encode_tls_cipher_text(Type, {MajVer, MinVer}, Epoch, Seq, Fragment) when MajVer >= 128->
    Length = erlang:iolist_size(Fragment),
    [<<?BYTE(Type), ?BYTE(MajVer), ?BYTE(MinVer), ?UINT16(Epoch),
       ?UINT48(Seq), ?UINT16(Length)>>, Fragment];
encode_tls_cipher_text(Type, {MajVer, MinVer}, _Epoch, _SeqNo, Fragment) ->
    Length = erlang:iolist_size(Fragment),
    [<<?BYTE(Type), ?BYTE(MajVer), ?BYTE(MinVer), ?UINT16(Length)>>, Fragment].

cipher(Type, Version, Fragment, CS0) ->
    Length = erlang:iolist_size(Fragment),
    {MacHash, CS1=#connection_state{cipher_state = CipherS0,
				 security_parameters=
				 #security_parameters{bulk_cipher_algorithm = 
						      BCA}
				}} = 
	hash_and_bump_seqno(CS0, Type, Version, Length, Fragment),
    {Ciphered, CipherS1} = ssl_cipher:cipher(BCA, CipherS0, MacHash, Fragment, Version),
    CS2 = CS1#connection_state{cipher_state=CipherS1},
    {Ciphered, CS2}.

decipher(TLS=#ssl_tls{type=Type, version=Version={254, _},
		      epoch = Epoch, sequence = SeqNo,
		      fragment=Fragment}, CS0) ->
    SP = CS0#connection_state.security_parameters,
    BCA = SP#security_parameters.bulk_cipher_algorithm,
    HashSz = SP#security_parameters.hash_size,
    CipherS0 = CS0#connection_state.cipher_state,
    case ssl_cipher:decipher(BCA, HashSz, CipherS0, Fragment, Version) of
	{T, Mac, CipherS1} ->
	    CS1 = CS0#connection_state{cipher_state = CipherS1},
	    TLength = size(T),
	    MacHash = hash_with_seqno(CS1, Type, Version, Epoch, SeqNo, TLength, T),
	    case is_correct_mac(Mac, MacHash) of
		true ->
		    {TLS#ssl_tls{fragment = T}, CS1};
		false ->
		    ?ALERT_REC(?FATAL, ?BAD_RECORD_MAC)
	    end;
	#alert{} = Alert ->
	    Alert
    end;

decipher(TLS=#ssl_tls{type=Type, version=Version, fragment=Fragment}, CS0) ->
    SP = CS0#connection_state.security_parameters,
    BCA = SP#security_parameters.bulk_cipher_algorithm, 
    HashSz = SP#security_parameters.hash_size,
    CipherS0 = CS0#connection_state.cipher_state,
    case ssl_cipher:decipher(BCA, HashSz, CipherS0, Fragment, Version) of
	{T, Mac, CipherS1} ->
	    CS1 = CS0#connection_state{cipher_state = CipherS1},
	    TLength = size(T),
	    {MacHash, CS2} = hash_and_bump_seqno(CS1, Type, Version, TLength, T),
	    case is_correct_mac(Mac, MacHash) of
		true ->		  
		    {TLS#ssl_tls{fragment = T}, CS2};
		false ->
		    ?ALERT_REC(?FATAL, ?BAD_RECORD_MAC)
	    end;
	#alert{} = Alert ->
	    Alert
    end.

uncompress(?NULL, Data = #ssl_tls{type = _Type,
				  version = _Version,
				  fragment = _Fragment}, CS) ->
    {Data, CS}.

compress(?NULL, Data, CS) ->
    {Data, CS}.

hash_with_seqno(#connection_state{mac_secret = MacSecret,
				 security_parameters =
				     SecPars},
	       Type, Version = {254, _},
	       Epoch, SeqNo, Length, Fragment) ->
    mac_hash(Version,
	     SecPars#security_parameters.mac_algorithm,
	     MacSecret, (Epoch bsl 48) + SeqNo, Type,
	     Length, Fragment).

hash_and_bump_seqno(#connection_state{epoch = Epoch,
				      sequence_number = SeqNo,
				      mac_secret = MacSecret,
				      security_parameters =
				      SecPars} = CS0,
		    Type, Version = {254, _}, Length, Fragment) ->
    Hash = mac_hash(Version,
		    SecPars#security_parameters.mac_algorithm,
		    MacSecret, (Epoch bsl 48) + SeqNo, Type,
		    Length, Fragment),
    {Hash, CS0#connection_state{sequence_number = SeqNo+1}};
hash_and_bump_seqno(#connection_state{sequence_number = SeqNo,
				      mac_secret = MacSecret,
				      security_parameters = 
				      SecPars} = CS0,
		    Type, Version, Length, Fragment) ->
    Hash = mac_hash(Version, 
		    SecPars#security_parameters.mac_algorithm,
		    MacSecret, SeqNo, Type,
		    Length, Fragment),
    {Hash, CS0#connection_state{sequence_number = SeqNo+1}}.

connection_state_next_epoch(undefined) ->
    0;
connection_state_next_epoch(State) ->
    State#connection_state.epoch + 1.

is_correct_mac(Mac, Mac) ->
    true;
is_correct_mac(_M,_H) ->
    false.

mac_hash({_,_}, ?NULL, _MacSecret, _SeqNo, _Type,
	 _Length, _Fragment) ->
    <<>>;
mac_hash({3, 0}, MacAlg, MacSecret, SeqNo, Type, Length, Fragment) ->
    ssl_ssl3:mac_hash(MacAlg, MacSecret, SeqNo, Type, Length, Fragment);
mac_hash({Major, Minor} = Version, MacAlg, MacSecret, SeqNo, Type, Length, Fragment)
  when (Major == 3 andalso Minor >= 1) orelse
       Major == 254 ->
    ssl_tls1:mac_hash(MacAlg, MacSecret, SeqNo, Type, Version,
		      Length, Fragment).

sufficient_tlsv1_2_crypto_support() ->
    proplists:get_bool(sha256, crypto:algorithms()).

protocol_version_atom(stream) ->
    protocol_version;
protocol_version_atom(datagram) ->
    protocol_version_datagram.
