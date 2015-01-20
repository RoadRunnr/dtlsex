-module(ssl_datagram).

-include("ssl_record.hrl").
-include("ssl_internal.hrl").
-include("ssl_handshake.hrl").

-export([handle_packet/3]).

handle_packet(Address, Port, Packet) ->

    try ssl_record:get_tls_records(Packet, <<>>) of
	%% expect client hello
	{[#ssl_tls{type = ?HANDSHAKE, version = {254, _}} = Record], <<>>} ->
	    handle_dtls_client_hello(Address, Port, Record);
	_ ->
	    {error, not_dtls}
    catch
	_:_ ->
	    {error, not_dtls}
    end.

handle_dtls_client_hello(Address, Port,
			 #ssl_tls{epoch = Epoch, sequence = Seq,
				  version = Version} = Record) ->
    {[{Hello, _}], _, _} =
	ssl_handshake:get_dtls_handshake(Record,
					 ssl_handshake:dtls_handshake_new_flight(undefined)),
    #client_hello{client_version = {Major, Minor},
		  random = Random,
		  session_id = SessionId,
		  cipher_suites = CipherSuites,
		  compression_methods = CompressionMethods} = Hello,
    CookieData = [address_to_bin(Address, Port),
		  <<?BYTE(Major), ?BYTE(Minor)>>,
		  Random, SessionId, CipherSuites, CompressionMethods],
    Cookie = crypto:hmac(sha, <<"secret">>, CookieData),

    case Hello of
	#client_hello{cookie = Cookie} ->
	    accept;

	_ ->
	    %% generate HelloVerifyRequest
	    {RequestFragment, _} = ssl_handshake:encode_handshake(
				     ssl_handshake:hello_verify_request(Cookie),
				     Version, 0, 1400),
	    HelloVerifyRequest =
		ssl_record:encode_tls_cipher_text(?HANDSHAKE, Version, Epoch, Seq, RequestFragment),
	    {reply, HelloVerifyRequest}
    end.

address_to_bin({A,B,C,D}, Port) ->
    <<0:80,16#ffff:16,A,B,C,D,Port:16>>;
address_to_bin({A,B,C,D,E,F,G,H}, Port) ->
    <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16,Port:16>>.
