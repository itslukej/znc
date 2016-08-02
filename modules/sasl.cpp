/*
 * Copyright (C) 2004-2016 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <algorithm>

#ifdef HAVE_LIBSSL
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif

static const struct {
    const char* szName;
    const char* szDescription;
    const bool bDefault;
} SupportedMechanisms[] = {
      {"EXTERNAL", "TLS certificate, for use with the *cert module", true},
      {"PLAIN",
       "Plain text negotiation, this should work always if the network "
       "supports SASL", true},
#ifdef HAVE_LIBSSL
      {"ECDSA-NIST256P-CHALLENGE", "ECDSA public key authentication", true},
#endif
};

#ifdef HAVE_LIBSSL
class ECDACommon {
private:
    EC_KEY *key;
    bool loaded;

public:
    ECDACommon() {
        key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);
        loaded = false;
    }

    ~ECDACommon() {
        if (key)
            EC_KEY_free(key);
    }

    /* Generate an ECC keypair suitable for authentication. */
    void GenerateKey(void) {
        EC_KEY_generate_key(key);
        loaded = true;
    }

    /* Get base64 encoded private key from key */
    CString GetPubBase64(void) {
        CString ret;
        size_t keybuflen;
        unsigned char *keybuf;

        if (!loaded)
            return ret;

        keybuflen = (size_t) i2o_ECPublicKey(key, NULL);
        keybuf = (unsigned char *)malloc(keybuflen);
        if (!keybuf)
            return ret;

        if (!i2o_ECPublicKey(key, &keybuf)) {
            free(keybuf);
            return ret;
        }
        /* for some reason keybuf is at the end now ?! */
        keybuf -= keybuflen;

        ret = CString((char *)keybuf, keybuflen);
        ret.Base64Encode();

        free(keybuf);
        return ret;
    }

    /* returns false if key fails to parse */
    bool LoadKey(const CString& sPath) {
        FILE *keyfile;
        CString path = sPath + "/sasl.pem";
        keyfile = fopen(path.c_str(), "r");
        if (keyfile == NULL) {
            loaded = false;
            return loaded;
        }

        PEM_read_ECPrivateKey(keyfile, &key, NULL, NULL);
        fclose(keyfile);

        EC_KEY_set_conv_form(key, POINT_CONVERSION_COMPRESSED);

        if (!EC_KEY_check_key(key))
            loaded = false;
        else
            loaded = true;

        return loaded;
    }

    bool SaveKey(const CString& sPath) {
        FILE *keyfile;
        CString path = sPath + "/sasl.pem";
        if (!loaded)
            return loaded;
        keyfile = fopen(path.c_str(), "w");
        if (keyfile == NULL)
            return false;
        PEM_write_ECPrivateKey(keyfile, key, NULL, NULL, 0, NULL, NULL);
        fclose(keyfile);
        return true;
    }

    CString Sign(const CString& challenge) {
        CString ret;
        CString ch;
        unsigned char *sigbuf;
        unsigned int siglen;

        if (!loaded)
            return ret;

        siglen = ECDSA_size(key);
        sigbuf = (unsigned char *)malloc(siglen);
        if (!sigbuf)
            return ret;

        ch = challenge.Base64Decode_n();

        if (!ECDSA_sign(0, (unsigned char *)ch.c_str(), ch.size(), sigbuf, &siglen, key)) {
            free(sigbuf);
            return ret;
        }

        ret = CString((char *)sigbuf, siglen);
        ret.Base64Encode();
        free(sigbuf);

        return ret;
    }

};
#endif

#define NV_REQUIRE_AUTH "require_auth"
#define NV_MECHANISMS "mechanisms"

class Mechanisms : public VCString {
  public:
    void SetIndex(unsigned int uiIndex) { m_uiIndex = uiIndex; }

    unsigned int GetIndex() const { return m_uiIndex; }

    bool HasNext() const { return size() > (m_uiIndex + 1); }

    void IncrementIndex() { m_uiIndex++; }

    CString GetCurrent() const { return at(m_uiIndex); }

    CString GetNext() const {
        if (HasNext()) {
            return at(m_uiIndex + 1);
        }

        return "";
    }

  private:
    unsigned int m_uiIndex = 0;
};

class CSASLMod : public CModule {
  public:
    MODCONSTRUCTOR(CSASLMod) {
        AddCommand("Help",
                   static_cast<CModCommand::ModCmdFunc>(&CSASLMod::PrintHelp),
                   "search", "Generate this output");
        AddCommand("Set", static_cast<CModCommand::ModCmdFunc>(&CSASLMod::Set),
                   "<username> [<password>]",
                   "Set username and password for the mechanisms that need "
                   "them. Password is optional");
        AddCommand("Mechanism", static_cast<CModCommand::ModCmdFunc>(
                                    &CSASLMod::SetMechanismCommand),
                   "[mechanism[ ...]]",
                   "Set the mechanisms to be attempted (in order)");
        AddCommand(
            "RequireAuth",
            static_cast<CModCommand::ModCmdFunc>(&CSASLMod::RequireAuthCommand),
            "[yes|no]", "Don't connect unless SASL authentication succeeds");
#ifdef HAVE_LIBSSL
        AddCommand(
            "GenerateKey",
            static_cast<CModCommand::ModCmdFunc>(&CSASLMod::GenerateKey),
            "", "Generate a key to use for ECDSA-NIST256P-CHALLENGE authentication");
        AddCommand(
            "ShowKey",
            static_cast<CModCommand::ModCmdFunc>(&CSASLMod::ShowKey),
            "",
            "Prints base64 encoded key for ECDSA-NIST256P-CHALLENGE authentication");
#endif
        AddCommand("Verbose", "yes|no", "Set verbosity level, useful to debug",
                   [&](const CString& sLine) {
            m_bVerbose = sLine.Token(1, true).ToBool();
            PutModule("Verbose: " + CString(m_bVerbose));
        });

        m_bStartedECDSA = false;
        m_bAuthenticated = false;
    }

    void PrintHelp(const CString& sLine) {
        HandleHelpCommand(sLine);

        CTable Mechanisms;
        Mechanisms.AddColumn("Mechanism");
        Mechanisms.AddColumn("Description");

        for (const auto& it : SupportedMechanisms) {
            Mechanisms.AddRow();
            Mechanisms.SetCell("Mechanism", it.szName);
            Mechanisms.SetCell("Description", it.szDescription);
        }

        PutModule("The following mechanisms are available:");
        PutModule(Mechanisms);
    }

    void Set(const CString& sLine) {
        SetNV("username", sLine.Token(1));
        SetNV("password", sLine.Token(2));

        PutModule("Username has been set to [" + GetNV("username") + "]");
        PutModule("Password has been set to [" + GetNV("password") + "]");
    }

    void SetMechanismCommand(const CString& sLine) {
        CString sMechanisms = sLine.Token(1, true).AsUpper();

        if (!sMechanisms.empty()) {
            VCString vsMechanisms;
            sMechanisms.Split(" ", vsMechanisms);

            for (const CString& sMechanism : vsMechanisms) {
                if (!SupportsMechanism(sMechanism)) {
                    PutModule("Unsupported mechanism: " + sMechanism);
                    return;
                }
            }

            SetNV(NV_MECHANISMS, sMechanisms);
        }

        PutModule("Current mechanisms set: " + GetMechanismsString());
    }

    void RequireAuthCommand(const CString& sLine) {
        if (!sLine.Token(1).empty()) {
            SetNV(NV_REQUIRE_AUTH, sLine.Token(1));
        }

        if (GetNV(NV_REQUIRE_AUTH).ToBool()) {
            PutModule("We require SASL negotiation to connect");
        } else {
            PutModule("We will connect even if SASL fails");
        }
    }

    bool SupportsMechanism(const CString& sMechanism) const {
        for (const auto& it : SupportedMechanisms) {
            if (sMechanism.Equals(it.szName)) {
                return true;
            }
        }

        return false;
    }

    CString GetMechanismsString() const {
        if (GetNV(NV_MECHANISMS).empty()) {
            CString sDefaults = "";

            for (const auto& it : SupportedMechanisms) {
                if (it.bDefault) {
                    if (!sDefaults.empty()) {
                        sDefaults += " ";
                    }

                    sDefaults += it.szName;
                }
            }

            return sDefaults;
        }

        return GetNV(NV_MECHANISMS);
    }

    void CheckRequireAuth() {
        if (!m_bAuthenticated && GetNV(NV_REQUIRE_AUTH).ToBool()) {
            GetNetwork()->SetIRCConnectEnabled(false);
            PutModule("Disabling network, we require authentication.");
            PutModule("Use 'RequireAuth no' to disable.");
        }
    }

#ifdef HAVE_LIBSSL
    void GenerateKey(const CString& sLine) {
        ECDACommon ec;
        CString key;

        ec.GenerateKey();
        ec.SaveKey(GetSavePath());
        key = ec.GetPubBase64();
        PutModule("New public key " + key + " generated");
    }

    void ShowKey(const CString& sLine) {
        ECDACommon ec;

        if (!ec.LoadKey(GetSavePath()))
            PutModule("No valid public key found");
        else
            PutModule("Public key: " + ec.GetPubBase64());
    }

    void AuthenticateECDSA(const CString& sLine) {
        ECDACommon ec;

        /* First call we just send username */
        if (!m_bStartedECDSA) {
            PutIRC("AUTHENTICATE " + GetNV("username").Base64Encode_n());
            m_bStartedECDSA = true;
            return;
        }
        m_bStartedECDSA = false;

        /* Load key then sign and send */
        if (!ec.LoadKey(GetSavePath())) {
            PutModule("No valid public key found");
            return;
        }
        PutIRC("AUTHENTICATE " + ec.Sign(sLine));
    }
#endif

    void Authenticate(const CString& sLine) {
        if (m_Mechanisms.GetCurrent().Equals("PLAIN") && sLine.Equals("+")) {
            CString sAuthLine = GetNV("username") + '\0' + GetNV("username") +
                                '\0' + GetNV("password");
            sAuthLine.Base64Encode();
            PutIRC("AUTHENTICATE " + sAuthLine);
#ifdef HAVE_LIBSSL
        } else if (m_Mechanisms.GetCurrent().Equals("ECDSA-NIST256P-CHALLENGE")) {
            AuthenticateECDSA(sLine);
#endif
        } else {
            /* Send blank authenticate for other mechanisms (like EXTERNAL). */
            PutIRC("AUTHENTICATE +");
        }
    }

    bool OnServerCapAvailable(const CString& sCap) override {
        return sCap.Equals("sasl");
    }

    void OnServerCapResult(const CString& sCap, bool bSuccess) override {
        if (sCap.Equals("sasl")) {
            if (bSuccess) {
                GetMechanismsString().Split(" ", m_Mechanisms);

                if (m_Mechanisms.empty()) {
                    CheckRequireAuth();
                    return;
                }

                GetNetwork()->GetIRCSock()->PauseCap();

                m_Mechanisms.SetIndex(0);
                PutIRC("AUTHENTICATE " + m_Mechanisms.GetCurrent());
            } else {
                CheckRequireAuth();
            }
        }
    }

    EModRet OnRawMessage(CMessage& msg) override {
        if (msg.GetCommand().Equals("AUTHENTICATE")) {
            Authenticate(msg.GetParam(0));
            return HALT;
        }
        return CONTINUE;
    }

    EModRet OnNumericMessage(CNumericMessage& msg) override {
        if (msg.GetCode() == 903) {
            /* SASL success! */
            if (m_bVerbose) {
                PutModule(m_Mechanisms.GetCurrent() + " mechanism succeeded.");
            }
            GetNetwork()->GetIRCSock()->ResumeCap();
            m_bAuthenticated = true;
            DEBUG("sasl: Authenticated with mechanism ["
                  << m_Mechanisms.GetCurrent() << "]");
        } else if (msg.GetCode() == 904 ||
                   msg.GetCode() == 905) {
            DEBUG("sasl: Mechanism [" << m_Mechanisms.GetCurrent()
                                      << "] failed.");
            if (m_bVerbose) {
                PutModule(m_Mechanisms.GetCurrent() + " mechanism failed.");
            }

            if (m_Mechanisms.HasNext()) {
                m_Mechanisms.IncrementIndex();
                PutIRC("AUTHENTICATE " + m_Mechanisms.GetCurrent());
            } else {
                CheckRequireAuth();
                GetNetwork()->GetIRCSock()->ResumeCap();
            }
        } else if (msg.GetCode() == 906) {
            /* CAP wasn't paused? */
            DEBUG("sasl: Reached 906.");
            CheckRequireAuth();
        } else if (msg.GetCode() == 907) {
            m_bAuthenticated = true;
            GetNetwork()->GetIRCSock()->ResumeCap();
            DEBUG("sasl: Received 907 -- We are already registered");
        } else {
            return CONTINUE;
        }
        return HALT;
    }

    void OnIRCConnected() override {
        /* Just incase something slipped through, perhaps the server doesn't
         * respond to our CAP negotiation. */

        CheckRequireAuth();
    }

    void OnIRCDisconnected() override {
        m_bAuthenticated = false;
        m_bStartedECDSA = false;
    }

    CString GetWebMenuTitle() override { return "SASL"; }

    bool OnWebRequest(CWebSock& WebSock, const CString& sPageName,
                      CTemplate& Tmpl) override {
#ifdef HAVE_LIBSSL
        ECDACommon ec;
#endif
        if (sPageName != "index") {
            // only accept requests to index
            return false;
        }

        if (WebSock.IsPost()) {
            SetNV("username", WebSock.GetParam("username"));
            CString sPassword = WebSock.GetParam("password");
            if (!sPassword.empty()) {
                SetNV("password", sPassword);
            }
            SetNV(NV_REQUIRE_AUTH, WebSock.GetParam("require_auth"));
            SetNV(NV_MECHANISMS, WebSock.GetParam("mechanisms"));
#ifdef HAVE_LIBSSL
            if(WebSock.HasParam("keygen")) {
                ec.GenerateKey();
                ec.SaveKey(GetSavePath());
            }
#endif
        }

        Tmpl["Username"] = GetNV("username");
        Tmpl["Password"] = GetNV("password");
        Tmpl["RequireAuth"] = GetNV(NV_REQUIRE_AUTH);
        Tmpl["Mechanisms"] = GetMechanismsString();
#ifdef HAVE_LIBSSL
        Tmpl["HaveLibSSL"] = "true";
        if (ec.LoadKey(GetSavePath()))
            Tmpl["PublicKey"] = ec.GetPubBase64();
#endif

        for (const auto& it : SupportedMechanisms) {
            CTemplate& Row = Tmpl.AddRow("MechanismLoop");
            CString sName(it.szName);
            Row["Name"] = sName;
            Row["Description"] = CString(it.szDescription);
        }

        return true;
    }

  private:
    Mechanisms m_Mechanisms;
    bool m_bAuthenticated;
    bool m_bStartedECDSA;
    bool m_bVerbose = false;
};

template <>
void TModInfo<CSASLMod>(CModInfo& Info) {
    Info.SetWikiPage("sasl");
}

NETWORKMODULEDEFS(CSASLMod,
                  "Adds support for sasl authentication capability to "
                  "authenticate to an IRC server")
