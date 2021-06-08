// mbedtls_context.cpp
//
// --------------------------------------------------------------------------
// This file is part of the "sockpp" C++ socket library.
//
// Copyright (c) 2014-2017 Frank Pagliughi
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// --------------------------------------------------------------------------

#include "sockpp/mbedtls_context.h"
#include "sockpp/connector.h"
#include "sockpp/exception.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mutex>
#include <chrono>
#include <cassert>

#ifdef __APPLE__
    #include <fcntl.h>
    #include <TargetConditionals.h>
    #ifdef TARGET_OS_OSX
        // For macOS read_system_root_certs():
        #include <Security/Security.h>
    #endif
#elif !defined(_WIN32)
    // For Unix read_system_root_certs():
    #include <dirent.h>
    #include <fcntl.h>
    #include <fnmatch.h>
    #include <fstream>
    #include <iostream>
    #include <sstream>
    #include <sys/stat.h>
#else
	//#include <wincrypt.h>
    #include <sstream>

    //#pragma comment (lib, "crypt32.lib")
	//#pragma comment (lib, "cryptui.lib")
#endif


namespace sockpp {
    using namespace std;


    static std::string read_system_root_certs();


    // Simple RAII helper for mbedTLS cert struct
    struct mbedtls_context::cert : public mbedtls_x509_crt
    {
        cert()  {mbedtls_x509_crt_init(this);}
        ~cert() {mbedtls_x509_crt_free(this);}
    };


    // Simple RAII helper for mbedTLS cert struct
    struct mbedtls_context::key : public mbedtls_pk_context
    {
        key()  {mbedtls_pk_init(this);}
        ~key() {mbedtls_pk_free(this);}
    };


#pragma mark - SOCKET:


    /** Concrete implementation of tls_socket using mbedTLS. */
    class mbedtls_socket : public tls_socket {
    private:
        mbedtls_context& context_;
        mbedtls_ssl_context ssl_;
        chrono::microseconds read_timeout_ {0L};
        bool open_ = false;

    public:

#ifdef MBEDTLS_DEBUG_C
        #define log(LEVEL, FMT,...) do { \
            auto ssl = &ssl_; \
            MBEDTLS_SSL_DEBUG_MSG(LEVEL, ("SockPP: " FMT, ## __VA_ARGS__)); \
        }while(0)
#else
    #define log(LEVEL, FMT,...) do { } while(0)
#endif


        int log_mbed_ret(int ret, const char *fn) {
            if (ret != 0) {
                char msg[100];
                mbedtls_strerror(ret, msg, sizeof(msg));
                log(1, "mbedtls error -0x%04X from %s: %s", -ret, fn, msg);
            }
            return ret;
        }


        mbedtls_socket(unique_ptr<stream_socket> base,
                       mbedtls_context &context,
                       const string &hostname)
        :tls_socket(move(base))
        ,context_(context)
        {
            mbedtls_ssl_init(&ssl_);
            if (context.status() != 0) {
                clear(context.status());
                return;
            }

            if (check_mbed_setup(mbedtls_ssl_setup(&ssl_, context_.ssl_config_.get()),
                               "mbedtls_ssl_setup"))
                return;
            if (!hostname.empty() && check_mbed_setup(mbedtls_ssl_set_hostname(&ssl_, hostname.c_str()),
                                                    "mbedtls_ssl_set_hostname"))
                return;

#if defined(_WIN32)
            // Winsock does not allow us to tell if a socket is nonblocking, so assume it isn't
            bool blocking = true;
#else
            int flags = fcntl(stream().handle(), F_GETFL, 0);
            bool blocking = (flags < 0 || (flags & O_NONBLOCK) == 0);
#endif
            setup_bio(blocking);

            // Run the TLS handshake:
            open_ = true;
            int status;
            do {
                status = mbedtls_ssl_handshake(&ssl_);
            } while (status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE
                            || status == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS);
            if (check_mbed_setup(status, "mbedtls_ssl_handshake") != 0)
                return;

            uint32_t verify_flags = mbedtls_ssl_get_verify_result(&ssl_);
            if (verify_flags != 0 && verify_flags != uint32_t(-1)
                                  && !(verify_flags & MBEDTLS_X509_BADCERT_SKIP_VERIFY)) {
                char vrfy_buf[512];
                mbedtls_x509_crt_verify_info(vrfy_buf, sizeof( vrfy_buf ), "", verify_flags);
                log(1, "Cert verify failed: %s", vrfy_buf );
                reset();
                clear(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
                return;
            }
        }


        void setup_bio(bool nonblocking) {
            mbedtls_ssl_send_t *f_send = [](void *ctx, const uint8_t *buf, size_t len) {
                return ((mbedtls_socket*)ctx)->bio_send(buf, len); };
            mbedtls_ssl_recv_t *f_recv = nullptr;
            mbedtls_ssl_recv_timeout_t *f_recv_timeout = nullptr;
            if (nonblocking)
                f_recv = [](void *ctx, uint8_t *buf, size_t len) {
                    return ((mbedtls_socket*)ctx)->bio_recv(buf, len); };
            else
                f_recv_timeout = [](void *ctx, uint8_t *buf, size_t len, uint32_t timeout) {
                    return ((mbedtls_socket*)ctx)->bio_recv_timeout(buf, len, timeout); };
            mbedtls_ssl_set_bio(&ssl_, this, f_send, f_recv, f_recv_timeout);
        }


        ~mbedtls_socket() {
            close();
            mbedtls_ssl_free(&ssl_);
            reset(); // remove bogus file descriptor so base class won't call close() on it
        }


        virtual bool close() override {
            if (open_) {
                mbedtls_ssl_close_notify(&ssl_);
                open_ = false;
            }
            return tls_socket::close();
        }


        // -------- certificate / trust API


        uint32_t peer_certificate_status() override {
            return mbedtls_ssl_get_verify_result(&ssl_);
        }


        string peer_certificate_status_message() override {
            uint32_t verify_flags = mbedtls_ssl_get_verify_result(&ssl_);
            if (verify_flags == 0 || verify_flags == UINT32_MAX)
                return "";
            char message[512];
            mbedtls_x509_crt_verify_info(message, sizeof( message ), "",
                                         verify_flags & ~MBEDTLS_X509_BADCERT_OTHER);
            size_t len = strlen(message);
            if (len > 0 && message[len] == '\0')
                --len;

            string result(message, len);
            if (verify_flags & MBEDTLS_X509_BADCERT_OTHER) {    // flag set by verify_callback()
                if (!result.empty())
                    result = "\n" + result;
                result = "The certificate does not match the known pinned certificate" + result;
            }
            return result;
        }


        string peer_certificate() override {
            auto cert = mbedtls_ssl_get_peer_cert(&ssl_);
            if (!cert) {
                // This should only happen in a failed handshake scenario, or if there
                // was no cert to begin with
                return context_.get_peer_certificate();
            }
            
            return string((const char*)cert->raw.p, cert->raw.len);
        }


        // -------- stream_socket I/O


        ssize_t read(void *buf, size_t length) override {
            return check_mbed_io( mbedtls_ssl_read(&ssl_, (uint8_t*)buf, length) );
        }


        ioresult read_r(void *buf, size_t length) override {
            return ioresult_from_mbed( mbedtls_ssl_read(&ssl_, (uint8_t*)buf, length) );
        }


        bool read_timeout(const chrono::microseconds& to) override {
            bool ok = stream().read_timeout(to);
            if (ok)
                read_timeout_ = to;
            return ok;
        }


        ssize_t write(const void *buf, size_t length) override {
            if (length == 0)
                return 0;
            return check_mbed_io( mbedtls_ssl_write(&ssl_, (const uint8_t*)buf, length) );
        }


        ioresult write_r(const void *buf, size_t length) override {
            if (length == 0)
                return {};
            return ioresult_from_mbed( mbedtls_ssl_write(&ssl_, (const uint8_t*)buf, length) );
        }


        bool write_timeout(const chrono::microseconds& to) override {
            return stream().write_timeout(to);
        }


        bool set_non_blocking(bool nonblocking) override {
            bool ok = stream().set_non_blocking(nonblocking);
            if (ok)
                setup_bio(nonblocking);
            return ok;
        }


        // -------- mbedTLS BIO callbacks


        int bio_send(const void* buf, size_t length) {
            if (!open_)
                return MBEDTLS_ERR_NET_CONN_RESET;
            return bio_return_value<false>(stream().write_r(buf, length));
        }


        int bio_recv(void* buf, size_t length) {
            if (!open_)
                return MBEDTLS_ERR_NET_CONN_RESET;
            return bio_return_value<true>(stream().read_r(buf, length));
        }


        int bio_recv_timeout(void* buf, size_t length, uint32_t timeout) {
            if (!open_)
                return MBEDTLS_ERR_NET_CONN_RESET;
            if (timeout > 0)
                stream().read_timeout(chrono::milliseconds(timeout));

            int n = bio_recv(buf, length);

            if (timeout > 0)
                stream().read_timeout(read_timeout_);
            return (int)n;
        }


        // -------- error handling


        // Translates mbedTLS error code to POSIX (errno)
        int translate_mbed_err(int mbedErr) {
            switch (mbedErr) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    return 0;
                case MBEDTLS_ERR_SSL_WANT_READ:
                case MBEDTLS_ERR_SSL_WANT_WRITE:
                    log(3, "mbedtls_socket returning EWOULDBLOCK");
                    return EWOULDBLOCK;
                case MBEDTLS_ERR_NET_CONN_RESET:
                    return ECONNRESET;
                case MBEDTLS_ERR_NET_RECV_FAILED:
                case MBEDTLS_ERR_NET_SEND_FAILED:
                    return EIO;
                default:
                    return mbedErr;
            }
        }


        // Handles an mbedTLS error return value during setup, closing me on error
        int check_mbed_setup(int ret, const char *fn) {
            if (ret != 0) {
                log_mbed_ret(ret, fn);
                int err = translate_mbed_err(ret);
                if (ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE)
                    err = mbedtls_context::FATAL_ERROR_ALERT_BASE - ssl_.in_msg[1];
                log(1, "---closing mbedtls_socket with error (mbed status -0x%x, last_error %d) ---", -ret, err);
                reset(); // marks me as closed/invalid
                clear(err); // sets last_error

                // Signal we're done by shutting down the socket's write stream. That lets the
                // client finish sending any data and receive our error alert. Wait until the
                // client closes, by reading data until we get 0 bytes, then finally close.
                stream().shutdown(SHUT_WR);
                stream().read_timeout(2000ms);
                char buf[100];
                while (stream().read(buf, sizeof(buf)) > 0)
                    ;
                stream().close();
                log(2, "--- closed mbedtls_socket ---");

                open_ = false;
            }
            return ret;
        }


        // Handles an mbedTLS read/write return value, storing any error in last_error
        inline ssize_t check_mbed_io(int mbedResult) {
            if (mbedResult < 0) {
                clear(translate_mbed_err(mbedResult));     // sets last_error
                return -1;
            }
            return mbedResult;
        }


        // Handles an mbedTLS read/write return value, converting it to an ioresult.
        inline ioresult ioresult_from_mbed(int mbedResult) {
            if (mbedResult < 0)
                return ioresult(0, translate_mbed_err(mbedResult));
            else
                return ioresult(mbedResult, 0);
        }


        // Translates ioresult to an mbedTLS error code to return from a BIO function.
        template <bool reading>
        int bio_return_value(ioresult result) {
            if (result.error == 0)
                return (int)result.count;
            switch (result.error) {
                case EPIPE:
                case ECONNRESET:
#ifdef _WIN32
                case WSAECONNRESET:
#endif
                    return MBEDTLS_ERR_NET_CONN_RESET;
                case EINTR:
                case EWOULDBLOCK:
#if defined(EAGAIN) && EAGAIN != EWOULDBLOCK    // these are usually synonyms
                case EAGAIN:
#endif
#ifdef _WIN32
                case WSAEINTR:
                case WSAEWOULDBLOCK:
#endif
                    log(3, ">>> BIO returning MBEDTLS_ERR_SSL_WANT_%s", reading ?"READ":"WRITE");
                    return reading ? MBEDTLS_ERR_SSL_WANT_READ
                                   : MBEDTLS_ERR_SSL_WANT_WRITE;
                default:
#ifdef _WIN32
                    log(3, ">>> BIO WSA error code %d results in a transfer error", result.error);
#else
                    log(3, ">>> BIO Error code %d results in a transfer error", result.error);
#endif
                    return reading ? MBEDTLS_ERR_NET_RECV_FAILED
                                   : MBEDTLS_ERR_NET_SEND_FAILED;
            }
        }
    };

    
    #undef log


#pragma mark - CONTEXT:


    static int log_mbed_ret(int ret, const char *fn) {
        if (ret != 0) {
            char msg[100];
            mbedtls_strerror(ret, msg, sizeof(msg));
            fprintf(stderr, "TLS: mbedtls error -0x%04X from %s: %s\n", -ret, fn, msg);
        }
        return ret;
    }


    static tls_context *s_default_context = nullptr;

    mbedtls_context::cert *mbedtls_context::s_system_root_certs;


    tls_context& tls_context::default_context() {
        if (!s_default_context)
            s_default_context = new mbedtls_context();
        return *s_default_context;
    }


    // Returns a shared mbedTLS random-number generator context.
    static mbedtls_ctr_drbg_context* get_drbg_context() {
        static const char* k_entropy_personalization = "sockpp";
        static mbedtls_entropy_context  s_entropy;
        static mbedtls_ctr_drbg_context s_random_ctx;

        static once_flag once;
        call_once(once, []() {
            mbedtls_entropy_init( &s_entropy );

            #if defined(_MSC_VER)
            #if !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
            auto uwp_entropy_poll = [](void *data, unsigned char *output, size_t len,
                                       size_t *olen) -> int
            {
                NTSTATUS status = BCryptGenRandom(NULL, output, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                if (status < 0) {
                    return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
                }

                *olen = len;
                return 0;
            };
            mbedtls_entropy_add_source(&s_entropy, uwp_entropy_poll, NULL, 32,
                                       MBEDTLS_ENTROPY_SOURCE_STRONG);
            #endif
            #endif
        
            mbedtls_ctr_drbg_init( &s_random_ctx );
            int ret = mbedtls_ctr_drbg_seed(&s_random_ctx, mbedtls_entropy_func, &s_entropy,
                                            (const uint8_t *)k_entropy_personalization,
                                            strlen(k_entropy_personalization));
            if (ret != 0) {
                log_mbed_ret(ret, "mbedtls_ctr_drbg_seed");
                throw sys_error(ret);   //FIXME: Not an errno; use different exception?
            }
        });
        return &s_random_ctx;
    }


    unique_ptr<mbedtls_context::cert> mbedtls_context::parse_cert(const std::string &cert_data, bool partialOk) {
        unique_ptr<cert> c(new cert);
        mbedtls_x509_crt_init(c.get());
        int ret = mbedtls_x509_crt_parse(c.get(),
                                         (const uint8_t*)cert_data.data(), cert_data.size() + 1);
        if (ret != 0) {
	        if(ret < 0 || !partialOk) {
		        log_mbed_ret(ret, "mbedtls_x509_crt_parse");
	        	if(ret > 0) {
	        		ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
	        	}

				throw sys_error(ret);
	        }
        }
        return c;
    }


    void mbedtls_context::set_root_certs(const std::string &cert_data) {
        root_certs_ = parse_cert(cert_data, true);
        mbedtls_ssl_conf_ca_chain(ssl_config_.get(), root_certs_.get(), nullptr);
    }


    // Returns the set of system trusted root CA certs.
    mbedtls_x509_crt* mbedtls_context::get_system_root_certs() {
        static once_flag once;
        call_once(once, []() {
            // One-time initialization:
            string certsPEM = read_system_root_certs();
            if (!certsPEM.empty())
                s_system_root_certs = parse_cert(certsPEM, true).release();
        });
        return s_system_root_certs;
    }


    mbedtls_context::mbedtls_context(role_t r)
    :ssl_config_(new mbedtls_ssl_config)
    {
        mbedtls_ssl_config_init(ssl_config_.get());
        mbedtls_ssl_conf_rng(ssl_config_.get(), mbedtls_ctr_drbg_random, get_drbg_context());
        int endpoint = (r == CLIENT) ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER;
        set_status(mbedtls_ssl_config_defaults(ssl_config_.get(),
                                               endpoint,
                                               MBEDTLS_SSL_TRANSPORT_STREAM,
                                               MBEDTLS_SSL_PRESET_DEFAULT));
        if (status() != 0)
            return;

        auto roots = get_system_root_certs();
        if (roots)
            mbedtls_ssl_conf_ca_chain(ssl_config_.get(), roots, nullptr);

        // Install a custom verification callback that will call my verify_callback():
        mbedtls_ssl_conf_verify(
                        ssl_config_.get(),
                        [](void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
                            return ((mbedtls_context*)ctx)->verify_callback(crt,depth,flags);
                        },
                        this);
    }


    mbedtls_context::~mbedtls_context() {
        mbedtls_ssl_config_free(ssl_config_.get());
    }


    int mbedtls_context::trusted_cert_callback(void *context,
                                               mbedtls_x509_crt const *child,
                                               mbedtls_x509_crt **candidates)
    {
        if (!root_cert_locator_)
            return -1;
        string certData((const char*)child->raw.p, child->raw.len);
        string rootData;
        if (!root_cert_locator_(certData, rootData))
            return -1;//TEMP
        if (rootData.empty()) {
            *candidates = nullptr;
        } else {
            // (can't use parse_cert() here because its return value uses RAII and will free itself)
            auto root = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt));
            mbedtls_x509_crt_init(root);
            int err = mbedtls_x509_crt_parse(root,
                                             (const uint8_t*)rootData.data(), rootData.size() + 1);
            if (err != 0) {
                mbedtls_x509_crt_free(root);
                free(root);
                return err;
            }
            *candidates = root;
        }
        return 0;
    }


    void mbedtls_context::set_root_cert_locator(RootCertLocator loc) {
        root_cert_locator_ = loc;
        mbedtls_x509_crt_ca_cb_t callback = nullptr;
        if (loc) {
            callback = [](void *ctx, mbedtls_x509_crt const *child, mbedtls_x509_crt **cand) {
                return ((mbedtls_context*)ctx)->trusted_cert_callback(ctx, child, cand);
            };
            mbedtls_ssl_conf_ca_cb(ssl_config_.get(), callback, this);
        } else {
            // Resetting this automatically clears the callback
            auto roots = get_system_root_certs();
            if (roots)
                mbedtls_ssl_conf_ca_chain(ssl_config_.get(), roots, nullptr);
        }
    }


    void mbedtls_context::set_logger(int threshold, Logger logger) {
        if (!logger_) {
            mbedtls_ssl_conf_dbg(ssl_config_.get(), [](void *ctx, int level, const char *file, int line,
                                                       const char *msg) {
                auto &logger = ((mbedtls_context*)ctx)->logger_;
                if (logger)
                    logger(level, file, line, msg);
            }, this);
        }
        logger_ = logger;
#ifdef MBEDTLS_DEBUG_C
        mbedtls_debug_set_threshold(threshold);
#endif
    }


    void mbedtls_context::require_peer_cert(role_t forRole, bool require, bool sendCAList) {
        if (forRole != role())
            return;
        int authMode = (require ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_authmode(ssl_config_.get(), authMode);

    	if(role() == SERVER) {
    		mbedtls_ssl_conf_cert_req_ca_list(ssl_config_.get(), sendCAList
				? MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED
				: MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);
		}
    }


    void mbedtls_context::allow_only_certificate(const std::string &cert_data) {
        if (cert_data.empty()) {
            pinned_cert_.reset();
        } else {
            pinned_cert_ = parse_cert(cert_data, false);
        }
    }


    void mbedtls_context::allow_only_certificate(mbedtls_x509_crt *certificate) {
        string cert_data;
        if (certificate) {
            cert_data = string((const char*)certificate->raw.p, certificate->raw.len);
        }
        allow_only_certificate(cert_data);
    }


    // callback from mbedTLS cert validation (see above)
    int mbedtls_context::verify_callback(mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
        if (depth != 0) {
            if(pinned_cert_) {
                // We only care that the end cert matches, clear all other errors
                *flags = 0;
            }
            
            return 0;
        }

        int status = -1;
        received_cert_data_ = string((const char *)crt->raw.p, crt->raw.len);
        
        if (pinned_cert_) {
            status = (crt->raw.len == pinned_cert_->raw.len
                      && 0 == memcmp(crt->raw.p, pinned_cert_->raw.p, crt->raw.len));
        } else if (auto &callback = get_auth_callback(); callback) {
            string certData((const char*)crt->raw.p, crt->raw.len);
            status = callback(certData);
        }
        
        if (status > 0) {
            *flags &= ~(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_CN_MISMATCH);
        } else if (status == 0) {
            *flags |= MBEDTLS_X509_BADCERT_OTHER;
        }
        return 0;
    }


    void mbedtls_context::set_identity(const std::string &certificate_data,
                                       const std::string &private_key_data)
    {
        auto ident_cert = parse_cert(certificate_data, false);

        unique_ptr<key> ident_key(new key);
        int err = mbedtls_pk_parse_key(ident_key.get(),
                                       (const uint8_t*) private_key_data.data(),
                                       private_key_data.size(), NULL, 0);
        if( err != 0 ) {
            log_mbed_ret(err, "mbedtls_pk_parse_key");
            throw sys_error(err);
        }

        set_identity(ident_cert.get(), ident_key.get());
        identity_cert_ = move(ident_cert);
        identity_key_  = move(ident_key);
    }


    void mbedtls_context::set_identity(mbedtls_x509_crt *certificate,
                                       mbedtls_pk_context *private_key)
    {
        mbedtls_ssl_conf_own_cert(ssl_config_.get(), certificate, private_key);
    }


    mbedtls_context::role_t mbedtls_context::role() {
        return (ssl_config_->endpoint == MBEDTLS_SSL_IS_CLIENT) ? CLIENT : SERVER;
    }


    unique_ptr<tls_socket> mbedtls_context::wrap_socket(std::unique_ptr<stream_socket> socket,
                                                        role_t socketRole,
                                                        const std::string &peer_name)
    {
        assert(socketRole == role());
        return make_unique<mbedtls_socket>(move(socket), *this, peer_name);
    }


#pragma mark - PLATFORM SPECIFIC:


    // mbedTLS does not have built-in support for reading the OS's trusted root certs.

#ifdef __APPLE__
    // Read system root CA certs on macOS.
    // (Sadly, SecTrustCopyAnchorCertificates() is not available on iOS)
    static string read_system_root_certs() {
    #if TARGET_OS_OSX
        CFArrayRef roots;
        OSStatus err = SecTrustCopyAnchorCertificates(&roots);
        if (err)
            return {};
        CFDataRef pemData = nullptr;
        err =  SecItemExport(roots, kSecFormatPEMSequence, kSecItemPemArmour, nullptr, &pemData);
        CFRelease(roots);
        if (err)
            return {};
        string pem((const char*)CFDataGetBytePtr(pemData), CFDataGetLength(pemData));
        CFRelease(pemData);
        return pem;
    #else
        // fallback -- no certs
        return "";
    #endif
    }

#elif defined(_WIN32)

	static const char* get_alphabet()
	{
		static constexpr char tab[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
		return &tab[0];
	}

	uint16_t getBase64EncodingSize(uint16_t size)
	{
		return 4 * ((size + 2) / 3);
	}

	static std::size_t encode64(void* dest, const void* src, std::size_t len)
	{
		char* out = static_cast<char*>(dest);
		const char* in = static_cast<const char*>(src);
		const auto tab = get_alphabet();

		for (auto n = len / 3; n--;) {
			*out++ = tab[(in[0] & 0xfc) >> 2];
			*out++ = tab[((in[0] & 0x03) << 4) + ((in[1] & 0xf0) >> 4)];
			*out++ = tab[((in[2] & 0xc0) >> 6) + ((in[1] & 0x0f) << 2)];
			*out++ = tab[in[2] & 0x3f];
			in += 3;
		}

		switch (len % 3) {
		case 2:
			*out++ = tab[(in[0] & 0xfc) >> 2];
			*out++ = tab[((in[0] & 0x03) << 4) + ((in[1] & 0xf0) >> 4)];
			*out++ = tab[(in[1] & 0x0f) << 2];
			*out++ = '=';
			break;

		case 1:
			*out++ = tab[(in[0] & 0xfc) >> 2];
			*out++ = tab[((in[0] & 0x03) << 4)];
			*out++ = '=';
			*out++ = '=';
			break;

		case 0: break;
		}

		return static_cast<std::size_t>(out - static_cast<char*>(dest));
	}

    // Windows:
    /*
    // This implementation presents certification issues due to the usage of wincrypt
    static string read_system_root_certs() {
        PCCERT_CONTEXT pContext = nullptr;
    	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, NULL,
			CERT_SYSTEM_STORE_CURRENT_USER, "ROOT");
        if(hStore == nullptr) {
            return "";
        }

        stringstream certs;
        while ((pContext = CertEnumCertificatesInStore(hStore, pContext))) {
            DWORD pCertPEMSize = 0;
            if (!CryptBinaryToStringA(pContext->pbCertEncoded, pContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, NULL, &pCertPEMSize)) {
                return "";
            }
            LPSTR pCertPEM = (LPSTR)malloc(pCertPEMSize);
            if (!CryptBinaryToStringA(pContext->pbCertEncoded, pContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, pCertPEM, &pCertPEMSize)) {
                return "";
            }
            certs.write(pCertPEM, pCertPEMSize);
            free(pCertPEM);
        }

        CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
        return certs.str();
    }
    */

   const char* CONCEPTS_PUBLIC_CERTIFICATE = "-----BEGIN CERTIFICATE-----#*MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB#*iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl#*cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV#*BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAw#*MjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV#*BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU#*aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy#*dGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK#*AoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B#*3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkY#*tJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+bJz/#*Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2#*VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT#*79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6#*c0Plfg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmT#*Yo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97l#*c6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4ee#*UB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeE#*Hg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd#*BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8G#*A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPF#*Up/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KO#*VWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3#*ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs#*8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR#*iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYze#*Sf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZ#*XHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/#*qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRB#*VXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGwsAvgnEzDHNb842m1R0aB#*L6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfG#*jjxDah2nGN59PRbxYvnKkKj9#*-----END CERTIFICATE-----#*";

   	// Windows:
	static string read_system_root_certs() {

		Windows::Security::Cryptography::Certificates::CertificateQuery cq;
		cq.StoreName(winrt::to_hstring("ROOT"));

		IAsyncOperation<IVectorView<Windows::Security::Cryptography::Certificates::Certificate> > allCertsOperation = CertificateStores::FindAllAsync(cq);

		while (allCertsOperation.Status() != AsyncStatus::Completed)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}

		IVectorView<Windows::Security::Cryptography::Certificates::Certificate> allCerts = allCertsOperation.GetResults();

		stringstream certs;

		std::string rootCert = CONCEPTS_PUBLIC_CERTIFICATE;
		std::replace(rootCert.begin(), rootCert.end(), (uint8_t)'#', (uint8_t)'\r');
		std::replace(rootCert.begin(), rootCert.end(), (uint8_t)'*', (uint8_t)'\n');
		//OutputDebugStringA("Certificate:\n");
		//OutputDebugStringA(rootCert.c_str());
		certs.write(rootCert.c_str(), rootCert.length());

		for (unsigned i = 0; i < allCerts.Size(); ++i)
		{
			Windows::Storage::Streams::IBuffer winrtData = allCerts.GetAt(i).GetCertificateBlob();

			char* buffer = (char*)malloc(winrtData.Length() + 1);

			for (int j = 0; j < winrtData.Length(); ++j)
				buffer[j] = winrtData.data()[j];

			buffer[winrtData.Length()] = '\0';

			std::string unencodedData(buffer);

			free(buffer);


			winrt::hstring base64Data = CryptographicBuffer::EncodeToBase64String(winrtData);

			std::string base64Data8bits = winrt::to_string(base64Data);

			for (auto j = 64; j < base64Data8bits.length(); j += 64)
			{
				if (j < base64Data8bits.length() - 1)
				{
					base64Data8bits.insert(j, "\r\n");
					j += 2;
				}
				else
				{
					break;
				}
			}

			base64Data8bits = "-----BEGIN CERTIFICATE-----\r\n" + base64Data8bits + "\r\n-----END CERTIFICATE-----\r\n";

			//OutputDebugStringA("Certificate:\n");
			//OutputDebugStringA(base64Data8bits.c_str());

			certs.write(base64Data8bits.c_str(), base64Data8bits.length());
		}

		return certs.str();
	}

#else
    // Read system root CA certs on Linux using OpenSSL's cert directory
    static string read_system_root_certs() {
#ifdef __ANDROID__
        static constexpr const char* CERTS_DIR  = "/system/etc/security/cacerts/";
#else
        static constexpr const char* CERTS_DIR  = "/etc/ssl/certs/";
        static constexpr const char* CERTS_FILE = "ca-certificates.crt";
#endif

        stringstream certs;
        char buf[1024];
        // Subroutine to append a file to the `certs` stream:
        auto read_file = [&](const string &file) {
            ifstream in(file);
            char last_char = '\n';
            while (in) {
                in.read(buf, sizeof(buf));
                auto n = in.gcount();
                if (n > 0) {
                    certs.write(buf, n);
                    last_char = buf[n-1];
                }
            }
            if (last_char != '\n')
                certs << '\n';
        };

        struct stat s;
        if (stat(CERTS_DIR, &s) == 0 && S_ISDIR(s.st_mode)) {
#ifndef __ANDROID__
            string certs_file = string(CERTS_DIR) + CERTS_FILE;
            if (stat(certs_file.c_str(), &s) == 0) {
                // If there is a file containing all the certs, just read it:
                read_file(certs_file);
            } else
#endif
            {
                // Otherwise concatenate all the certs found in the dir:
                auto dir = opendir(CERTS_DIR);
                if (dir) {
                    struct dirent *ent;
                    while (nullptr != (ent = readdir(dir))) {
#ifndef __ANDROID__
                        if (fnmatch("?*.pem", ent->d_name, FNM_PERIOD) == 0
                                    || fnmatch("?*.crt", ent->d_name, FNM_PERIOD) == 0)
#endif
                            read_file(string(CERTS_DIR) + ent->d_name);
                    }
                    closedir(dir);
                }
            }
        }
        return certs.str();
    }

#endif


}
