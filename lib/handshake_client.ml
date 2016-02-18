open Nocrypto

open Utils

open Core
open State
open Handshake_common
open Config

let (<+>) = Cs.(<+>)

let default_client_hello config =
  let host = match config.peer_name with
    | None   -> []
    | Some x -> [`Hostname x]
  in
  let version = max_protocol_version config.protocol_versions in
  let extensions, psk, secrets = match version with
    | TLS_1_0 | TLS_1_1 -> ([], false, [])
    | TLS_1_2 ->
       let supported = List.map (fun h -> (h, Packet.RSA)) config.hashes in
       ([`SignatureAlgorithms supported], false, [])
    | TLS_1_3 ->
       let sig_alg =
         List.fold_left
           (fun acc h ->
            (h, Packet.RSA) :: (h, Packet.RSAPSS) :: acc)
           [] config.hashes
       and groups =
         List.map Ciphersuite.group_to_any_group config.groups
       and keyshares, secrets =
         let secrets, shares = List.split (List.map Dh.gen_key config.groups) in
         (List.combine
            (List.map Ciphersuite.group_to_any_group config.groups)
            shares,
          List.combine config.groups secrets)
       in
       let exts =
         [`SignatureAlgorithms sig_alg ; `SupportedGroups groups ; `KeyShare keyshares ]
       in
       let psk = match config.cached_session with
         | Some { psk_id ; _ } when Cstruct.len psk_id > 0 -> [`PreSharedKey [ psk_id ]]
         | _ -> []
       in
       (exts @ psk, List.length psk > 0, secrets)
  in
  let ciphers =
    let cs = config.ciphers in
    match version with
    | TLS_1_0 | TLS_1_1 -> List.filter (o not Ciphersuite.ciphersuite_tls12_only) cs
    | TLS_1_2 -> cs
    | TLS_1_3 -> if psk then cs else List.filter (o not Ciphersuite.ciphersuite_psk) cs
  and sessionid =
    match config.use_reneg, config.cached_session with
    | _, Some { session_id ; extended_ms ; _ } when extended_ms && not (Cs.null session_id) -> Some session_id
    | false, Some { session_id ; _ } when not (Cs.null session_id) -> Some session_id
    | _ -> None
  in
  let ch = {
    client_version = Supported version ;
    client_random  = Rng.generate 32 ;
    sessionid      = sessionid ;
    ciphersuites   = List.map Ciphersuite.ciphersuite_to_any_ciphersuite ciphers ;
    extensions     = host @ extensions @ [`ExtendedMasterSecret]
  }
  in
  (ch, version, secrets)

let validate_cipher suites suite =
  guard (List.mem suite suites) (`Error (`NoConfiguredCiphersuite [suite]))

let answer_server_hello state (ch : client_hello) sh secrets raw log =
  let validate_version requested (lo, _) server_version =
    guard (version_ge requested server_version && server_version >= lo)
      (`Error (`NoConfiguredVersion server_version))

  and validate_reneg data =
    match data with
    | Some x -> guard (Cs.null x) (`Fatal `InvalidRenegotiation)
    | None -> return ()
  in

  let cfg = state.config in
  guard (server_hello_valid sh) (`Fatal `InvalidServerHello) >>= fun () ->
  guard (server_exts_subset_of_client sh.extensions ch.extensions) (`Fatal `InvalidServerHello) >>= fun () ->
  validate_version ch.client_version state.config.protocol_versions sh.server_version >>= fun () ->
  validate_cipher cfg.ciphers sh.ciphersuite >>= fun () ->

  (let piece = Cstruct.sub sh.server_random 0 8 in
   match any_version_to_version ch.client_version, sh.server_version with
   | Some TLS_1_3, x when x = TLS_1_2 || x = TLS_1_1 || x = TLS_1_0 ->
     guard (not (Cs.equal downgrade13 piece)) (`Fatal `InvalidServerHello)
   | Some TLS_1_2, x when x = TLS_1_1 || x = TLS_1_0 ->
     guard (not (Cs.equal downgrade12 piece)) (`Fatal `InvalidServerHello)
   | _ -> return ()) >>= fun () ->

  let epoch_matches (epoch : epoch_data) =
    epoch.ciphersuite = sh.ciphersuite &&
      epoch.protocol_version = sh.server_version &&
        option false (SessionID.equal epoch.session_id) sh.sessionid &&
          (not cfg.use_reneg ||
             (List.mem `ExtendedMasterSecret sh.extensions && epoch.extended_ms))
  in

  Tracing.sexpf ~tag:"version" ~f:sexp_of_tls_version sh.server_version ;
  trace_cipher sh.ciphersuite ;

  let state = { state with protocol_version = sh.server_version } in
  match sh.server_version with
  | TLS_1_3 -> Handshake_client13.answer_server_hello state ch sh secrets raw (Cs.appends log)
  | TLS_1_0 | TLS_1_1 | TLS_1_2 ->
    validate_reneg (get_secure_renegotiation sh.extensions) >|= fun () ->
    match state.config.cached_session with
    | Some epoch when epoch_matches epoch ->
       let session = session_of_epoch epoch in
       let session = { session with
                       client_random = ch.client_random ;
                       server_random = sh.server_random ;
                       client_version = ch.client_version ;
                       client_auth = List.length epoch.own_certificate > 0 ;
                     }
       in
       let client_ctx, server_ctx =
         Handshake_crypto.initialise_crypto_ctx sh.server_version session
       in
       let machina = AwaitServerChangeCipherSpecResume (session, client_ctx, server_ctx, log @ [raw]) in
       ({ state with machina = Client machina }, [])
    | _ ->
       let machina =
         let cipher = sh.ciphersuite in
         let session_id = match sh.sessionid with None -> Cstruct.create 0 | Some x -> x in
         let extended_ms =
           List.mem `ExtendedMasterSecret ch.extensions &&
             List.mem `ExtendedMasterSecret sh.extensions
         in
         let session = { empty_session with
                         client_random    = ch.client_random ;
                         client_version   = ch.client_version ;
                         server_random    = sh.server_random ;
                         ciphersuite      = cipher ;
                         session_id ;
                         extended_ms ;
                       }
         in
         Ciphersuite.(match ciphersuite_kex cipher with
                      | RSA     -> AwaitCertificate_RSA (session, log @ [raw])
                      | DHE_RSA -> AwaitCertificate_DHE_RSA (session, log @ [raw]))
       in
       ({ state with machina = Client machina }, [])

let answer_server_hello_renegotiate state session (ch : client_hello) sh raw log =
  let validate_reneg reneg data =
    match reneg, data with
    | (cvd, svd), Some x -> guard (Cs.equal (cvd <+> svd) x) (`Fatal `InvalidRenegotiation)
    | _ -> fail (`Fatal `NoSecureRenegotiation)
  in

  let cfg = state.config in
  guard (server_hello_valid sh &&
         server_exts_subset_of_client sh.extensions ch.extensions)
    (`Fatal `InvalidServerHello)
  >>= fun () ->
  guard (state.protocol_version = sh.server_version)
    (`Fatal (`InvalidRenegotiationVersion sh.server_version)) >>= fun () ->
  validate_cipher cfg.ciphers sh.ciphersuite >>= fun () ->
  let theirs = get_secure_renegotiation sh.extensions in
  validate_reneg session.renegotiation theirs >|= fun () ->

  let machina =
    let cipher = sh.ciphersuite in
    let session = { empty_session with
      ciphersuite      = cipher ;
      server_random    = sh.server_random ;
      client_random    = ch.client_random ;
      client_version   = ch.client_version
    } in
    Ciphersuite.(match ciphersuite_kex cipher with
                 | RSA     -> AwaitCertificate_RSA (session, log @ [raw])
                 | DHE_RSA -> AwaitCertificate_DHE_RSA (session, log @ [raw]))
  in
  ({ state with machina = Client machina }, [])

let validate_keytype_usage certificate ciphersuite =
  let keytype, usage =
    Ciphersuite.(o required_keytype_and_usage ciphersuite_kex ciphersuite)
  in
  match certificate with
  | None -> fail (`Fatal `NoCertificateReceived)
  | Some cert ->
    let open X509 in
    guard (supports_keytype cert keytype)
      (`Fatal `NotRSACertificate) >>= fun () ->
    guard (Extension.supports_usage ~not_present:true cert usage)
      (`Fatal `InvalidCertificateUsage) >>= fun () ->
    guard
      (Extension.supports_extended_usage cert `Server_auth ||
       Extension.supports_extended_usage ~not_present:true cert `Any)
      (`Fatal `InvalidCertificateExtendedUsage)

let answer_certificate_RSA state session cs raw log =
  let cfg = state.config in
  let peer_name = match cfg.peer_name with
    | None   -> None
    | Some x -> Some (`Wildcard x)
  in
  validate_chain cfg.authenticator cs peer_name >>= fun (peer_certificate, received_certificates, peer_certificate_chain, trust_anchor) ->
  validate_keytype_usage peer_certificate session.ciphersuite >>= fun () ->
  let session = { session with received_certificates ; peer_certificate ; peer_certificate_chain ; trust_anchor } in
  ( match session.client_version with
    | Supported v -> return v
    | x           -> fail (`Fatal (`NoVersion x)) (* TODO: get rid of this... *)
  ) >>= fun version ->
  let ver = Writer.assemble_protocol_version version in
  let premaster = ver <+> Rng.generate 46 in
  peer_rsa_key peer_certificate >|= fun pubkey ->
  let kex = Rsa.PKCS1.encrypt pubkey premaster
  in

  let machina =
    AwaitCertificateRequestOrServerHelloDone
      (session, kex, premaster, log @ [raw])
  in
  ({ state with machina = Client machina }, [])

let answer_certificate_DHE_RSA state session cs raw log =
  let peer_name = match state.config.peer_name with
    | None   -> None
    | Some x -> Some (`Wildcard x)
  in
  validate_chain state.config.authenticator cs peer_name >>= fun (peer_certificate, received_certificates, peer_certificate_chain, trust_anchor) ->
  validate_keytype_usage peer_certificate session.ciphersuite >|= fun () ->
  let session = { session with received_certificates ; peer_certificate ; peer_certificate_chain ; trust_anchor } in
  let machina = AwaitServerKeyExchange_DHE_RSA (session, log @ [raw]) in
  ({ state with machina = Client machina }, [])

let answer_server_key_exchange_DHE_RSA state session kex raw log =
  let dh_params kex =
    match Reader.parse_dh_parameters kex with
    | Ok data  -> return data
    | Error re -> fail (`Fatal (`ReaderError re))
  in

  dh_params kex >>= fun (dh_params, raw_dh_params, leftover) ->
  let sigdata = session.client_random <+> session.server_random <+> raw_dh_params in
  verify_digitally_signed state.protocol_version state.config.hashes leftover sigdata session.peer_certificate >>= fun () ->
  let group, shared = Crypto.dh_params_unpack dh_params in
  guard (Dh.modulus_size group >= Config.min_dh_size) (`Fatal `InvalidDH)
  >>= fun () ->

  let secret, kex = Dh.gen_key group in
  match Crypto.dh_shared group secret shared with
  | None     -> fail (`Fatal `InvalidDH)
  | Some pms -> let machina =
                  AwaitCertificateRequestOrServerHelloDone
                    (session, kex, pms, log @ [raw])
                in
                return ({ state with machina = Client machina }, [])

let answer_certificate_request state session cr kex pms raw log =
  let cfg = state.config in
  ( match state.protocol_version with
    | TLS_1_0 | TLS_1_1 ->
       ( match Reader.parse_certificate_request cr with
         | Ok (types, cas) -> return (types, None, cas)
         | Error re -> fail (`Fatal (`ReaderError re)) )
    | TLS_1_2 ->
       ( match Reader.parse_certificate_request_1_2 cr with
         | Ok (types, sigalgs, cas) -> return (types, Some sigalgs, cas)
         | Error re -> fail (`Fatal (`ReaderError re)) )
  ) >|= fun (types, sigalgs, cas) ->
  (* TODO: respect cas, maybe multiple client certificates? *)
  let own_certificate, own_private_key =
    match
      List.mem Packet.RSA_SIGN types,
      cfg.own_certificates
    with
    | true, `Single (chain, priv) -> (chain, Some priv)
    | _ -> ([], None)
  in
  let session = {
    session with
      own_certificate ;
      own_private_key ;
      client_auth = true
  } in
  let machina = AwaitServerHelloDone (session, sigalgs, kex, pms, log @ [raw]) in
  ({ state with machina = Client machina }, [])

let answer_server_hello_done state session sigalgs kex premaster raw log =
  let kex = ClientKeyExchange kex in
  let ckex = Writer.assemble_handshake kex in

  ( match session.client_auth, session.own_private_key with
    | true, Some p ->
       let cs = List.map X509.Encoding.cs_of_cert session.own_certificate in
       let cert = Certificate (Writer.assemble_certificates cs) in
       let ccert = Writer.assemble_handshake cert in
       let to_sign = log @ [ raw ; ccert ; ckex ] in
       let data = Cs.appends to_sign in
       let ver = state.protocol_version
       and my_sigalgs = state.config.hashes in
       signature ver data sigalgs my_sigalgs p >|= fun (signature) ->
       let cert_verify = CertificateVerify signature in
       let ccert_verify = Writer.assemble_handshake cert_verify in
       ([ cert ; kex ; cert_verify ],
        [ ccert ; ckex ; ccert_verify ],
        to_sign, Some ccert_verify)
    | true, None ->
       let cert = Certificate (Cstruct.create 0) in
       let ccert = Writer.assemble_handshake cert in
       return ([cert ; kex], [ccert ; ckex], log @ [ raw ; ccert ; ckex ], None)
    | false, _ ->
       return ([kex], [ckex], log @ [ raw ; ckex ], None) )
  >|= fun (msgs, raw_msgs, raws, cert_verify) ->

  let to_fin = raws @ option [] (fun x -> [x]) cert_verify in

  let master_secret =
    Handshake_crypto.derive_master_secret state.protocol_version session premaster raws
  in
  let session = { session with master_secret } in
  let client_ctx, server_ctx =
    Handshake_crypto.initialise_crypto_ctx state.protocol_version session
  in

  let checksum = Handshake_crypto.finished state.protocol_version session.ciphersuite master_secret "client finished" to_fin in
  let fin = Finished checksum in
  let raw_fin = Writer.assemble_handshake fin in
  let ps = to_fin @ [raw_fin] in

  let session = { session with master_secret = master_secret } in
  let machina = AwaitServerChangeCipherSpec (session, server_ctx, checksum, ps)
  and ccst, ccs = change_cipher_spec in

  List.iter (Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake) msgs;
  Tracing.cs ~tag:"change-cipher-spec-out" ccs ;
  Tracing.cs ~tag:"master-secret" master_secret;
  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake fin;

  ({ state with machina = Client machina },
   List.map (fun x -> `Record (Packet.HANDSHAKE, x)) raw_msgs @
     [ `Record (ccst, ccs);
       `Change_enc (Some client_ctx);
       `Record (Packet.HANDSHAKE, raw_fin)])

let answer_server_finished state session client_verify fin log =
  let computed =
    Handshake_crypto.finished state.protocol_version session.ciphersuite session.master_secret "server finished" log
  in
  guard (Cs.equal computed fin) (`Fatal `BadFinished) >>= fun () ->
  guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->
  let machina = Established
  and session = { session with renegotiation = (client_verify, computed) } in
  ({ state with machina = Client machina ; session = session :: state.session }, [])

let answer_server_finished_resume state session fin raw log =
  let client, server =
    let checksum = Handshake_crypto.finished state.protocol_version session.ciphersuite session.master_secret in
    (checksum "client finished" (log @ [raw]), checksum "server finished" log)
  in
  guard (Cs.equal server fin) (`Fatal `BadFinished) >>= fun () ->
  guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->
  let machina = Established
  and session = { session with renegotiation = (client, server) }
  in
  let finished = Finished client in
  let raw_finished = Writer.assemble_handshake finished in
  Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake finished ;
  ({ state with machina = Client machina ; session = session :: state.session },
   [`Record (Packet.HANDSHAKE, raw_finished)])

let answer_hello_request state =
  let produce_client_hello session config exts =
     let dch, _, _ = default_client_hello config in
     let ch = { dch with extensions = exts @ dch.extensions ; sessionid = None } in
     let raw = Writer.assemble_handshake (ClientHello ch) in
     let machina = AwaitServerHelloRenegotiate (session, ch, [raw]) in
     Tracing.sexpf ~tag:"handshake-out" ~f:sexp_of_tls_handshake (ClientHello ch) ;
     ({ state with machina = Client machina }, [`Record (Packet.HANDSHAKE, raw)])
  in

  match state.config.use_reneg, state.session with
  | true , x :: _ ->
    let ext = `SecureRenegotiation (fst x.renegotiation) in
    return (produce_client_hello x state.config [ext])
  | true , _      -> fail (`Fatal `InvalidSession) (* I'm pretty sure this can be an assert false *)
  | false, _      ->
    let no_reneg = Writer.assemble_alert ~level:Packet.WARNING Packet.NO_RENEGOTIATION in
    Tracing.sexpf ~tag:"alert-out" ~f:sexp_of_tls_alert (Packet.WARNING, Packet.NO_RENEGOTIATION) ;
    return (state, [`Record (Packet.ALERT, no_reneg)])

let handle_change_cipher_spec cs state packet =
  match Reader.parse_change_cipher_spec packet, cs with
  | Ok (), AwaitServerChangeCipherSpec (session, server_ctx, client_verify, log) ->
     guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->
     let machina = AwaitServerFinished (session, client_verify, log) in
     Tracing.cs ~tag:"change-cipher-spec-in" packet ;
     ({ state with machina = Client machina }, [`Change_dec (Some server_ctx)])
  | Ok (), AwaitServerChangeCipherSpecResume (session, client_ctx, server_ctx, log) ->
     guard (Cs.null state.hs_fragment) (`Fatal `HandshakeFragmentsNotEmpty) >|= fun () ->
     let ccs = change_cipher_spec in
     let machina = AwaitServerFinishedResume (session, log) in
     Tracing.cs ~tag:"change-cipher-spec-in" packet ;
     Tracing.cs ~tag:"change-cipher-spec-out" packet ;
     ({ state with machina = Client machina },
      [`Record ccs ; `Change_enc (Some client_ctx); `Change_dec (Some server_ctx)])
  | Error re, _ -> fail (`Fatal (`ReaderError re))
  | _ -> fail (`Fatal `UnexpectedCCS)

let handle_handshake cs hs buf =
  let open Reader in
  match parse_handshake buf with
  | Ok handshake ->
     Tracing.sexpf ~tag:"handshake-in" ~f:sexp_of_tls_handshake handshake ;
     ( match cs, handshake with
       | AwaitServerHello (ch, secrets, log), ServerHello sh ->
          answer_server_hello hs ch sh secrets buf log
       | AwaitServerHello (ch, secrets, log), HelloRetryRequest hrr ->
          Handshake_client13.answer_hello_retry_request hs ch hrr secrets buf (Cs.appends log)
       | AwaitServerHelloRenegotiate (session, ch, log), ServerHello sh ->
          answer_server_hello_renegotiate hs session ch sh buf log
       | AwaitCertificate_RSA (session, log), Certificate cs ->
          (match Reader.parse_certificates cs with
           | Or_error.Ok cs -> answer_certificate_RSA hs session cs buf log
           | Or_error.Error re -> fail (`Fatal (`ReaderError re)))
       | AwaitCertificate_DHE_RSA (session, log), Certificate cs ->
          (match Reader.parse_certificates cs with
           | Or_error.Ok cs -> answer_certificate_DHE_RSA hs session cs buf log
           | Or_error.Error re -> fail (`Fatal (`ReaderError re)))
       | AwaitServerKeyExchange_DHE_RSA (session, log), ServerKeyExchange kex ->
          answer_server_key_exchange_DHE_RSA hs session kex buf log
       | AwaitCertificateRequestOrServerHelloDone (session, kex, pms, log), CertificateRequest cr ->
          answer_certificate_request hs session cr kex pms buf log
       | AwaitCertificateRequestOrServerHelloDone (session, kex, pms, log), ServerHelloDone ->
          answer_server_hello_done hs session None kex pms buf log
       | AwaitServerHelloDone (session, sigalgs, kex, pms, log), ServerHelloDone ->
          answer_server_hello_done hs session sigalgs kex pms buf log
       | AwaitServerFinished (session, client_verify, log), Finished fin ->
          answer_server_finished hs session client_verify fin log
       | AwaitServerFinishedResume (session, log), Finished fin ->
          answer_server_finished_resume hs session fin buf log
       | Established, HelloRequest ->
          answer_hello_request hs
       | _, hs -> fail (`Fatal (`UnexpectedHandshake hs)) )
  | Error re -> fail (`Fatal (`ReaderError re))

