%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 2007-2012. All Rights Reserved.
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
%% Purpose: Handles ssl sessions
%%----------------------------------------------------------------------

-module(dtlsex_session).

-include("dtlsex_handshake.hrl").
-include("dtlsex_internal.hrl").

%% Internal application API
-export([is_new/2, client_id/4, server_id/6, valid_session/2]).

-define('24H_in_sec', 8640).

-type seconds()   :: integer(). 

%%--------------------------------------------------------------------
-spec is_new(session_id(), session_id()) -> boolean().
%%
%% Description: Checks if the session id decided by the server is a
%%              new or resumed sesion id.
%%--------------------------------------------------------------------
is_new(<<>>, _) ->
    true;
is_new(SessionId, SessionId) ->
    false;
is_new(_ClientSuggestion, _ServerDecision) ->
    true.

%%--------------------------------------------------------------------
-spec client_id({host(), inet:port_number(), #ssl_options{}}, db_handle(), atom(),
	 undefined | binary()) -> binary().
%%
%% Description: Should be called by the client side to get an id
%%              for the client hello message.
%%--------------------------------------------------------------------
client_id(ClientInfo, Cache, CacheCb, OwnCert) ->
    case select_session(ClientInfo, Cache, CacheCb, OwnCert) of
	no_session ->
	    <<>>;
	SessionId ->
	    SessionId
    end.

-spec valid_session(#session{}, seconds()) -> boolean().
%%
%% Description: Check that the session has not expired
%%--------------------------------------------------------------------
valid_session(#session{time_stamp = TimeStamp}, LifeTime) ->
    Now =  calendar:datetime_to_gregorian_seconds({date(), time()}),
    Now - TimeStamp < LifeTime.

server_id(Port, <<>>, _SslOpts, _Cert, _, _) ->
    {dtlsex_manager:new_session_id(Port), undefined};
server_id(Port, SuggestedId, Options, Cert, Cache, CacheCb) ->
    LifeTime = case application:get_env(dtlsex, session_lifetime) of
		   {ok, Time} when is_integer(Time) -> Time;
		   _ -> ?'24H_in_sec'
	       end,
    case is_resumable(SuggestedId, Port, Options,
		      Cache, CacheCb, LifeTime, Cert)
    of
	{true, Resumed} ->
	    {SuggestedId, Resumed};
	{false, undefined} ->
	    {dtlsex_manager:new_session_id(Port), undefined}
    end.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
select_session({_, _, #ssl_options{reuse_sessions=false}}, _Cache, _CacheCb, _OwnCert) ->
    no_session;
select_session({HostIP, Port, SslOpts}, Cache, CacheCb, OwnCert) ->
    Sessions = CacheCb:select_session(Cache, {HostIP, Port}),
    select_session(Sessions, SslOpts, OwnCert).

select_session([], _, _) ->
    no_session;
select_session(Sessions, #ssl_options{ciphers = Ciphers}, OwnCert) ->
    IsNotResumable =
	fun(Session) ->
		not (resumable(Session#session.is_resumable) andalso
		     lists:member(Session#session.cipher_suite, Ciphers)
		     andalso (OwnCert == Session#session.own_certificate))
 	end,
    case lists:dropwhile(IsNotResumable, Sessions) of
	[] ->   no_session;
	[Session | _] -> Session#session.session_id
    end.

is_resumable(_, _, #ssl_options{reuse_sessions = false}, _, _, _, _) ->
    {false, undefined};
is_resumable(SuggestedSessionId, Port, #ssl_options{reuse_session = ReuseFun} = Options, Cache,
	     CacheCb, SecondLifeTime, OwnCert) ->
    case CacheCb:lookup(Cache, {Port, SuggestedSessionId}) of
	#session{cipher_suite = CipherSuite,
		 own_certificate = SessionOwnCert,
		 compression_method = Compression,
		 is_resumable = IsResumable,
		 peer_certificate = PeerCert} = Session ->
	    case resumable(IsResumable)
		andalso (OwnCert == SessionOwnCert)
		andalso valid_session(Session, SecondLifeTime)
		andalso reusable_options(Options, Session)
		andalso ReuseFun(SuggestedSessionId, PeerCert,
				 Compression, CipherSuite)
	    of
		true  -> {true, Session};
		false -> {false, undefined}
	    end;
	undefined ->
	    {false, undefined}
    end.

resumable(new) ->
    false;
resumable(IsResumable) ->
    IsResumable.

reusable_options(#ssl_options{fail_if_no_peer_cert = true,
			   verify = verify_peer}, Session) ->
    (Session#session.peer_certificate =/= undefined);
reusable_options(_,_) ->
    true.
