package br.jus.tjmg.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.PKCS11;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_OS_LOCKING_OK;

/**
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 TJMG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
public class SeloCryptUtil {

    private static HashMap<String, List<String>> dll;
    private static final String DLLS_LINUX = "CERT_DIGITAL_APPLET_DLL_LINUX";
    private static final String DLLS_WINDOWS = "CERT_DIGITAL_APPLET_DLL_WINDOWS";
    private static final String CAMINHO_CHAVE_PUBLICA_TJMG = "/tjmg.cer";
    private static Provider tokenProvider;
    private static final String KEYSTORE_JKS = "JKS";
    private static final Logger logger = Logger.getLogger(SeloCryptUtil.class.getName());
    private static PublicKey chavePublicaTJMG = null;

    private SeloCryptUtil() {
    }

    static {
        try {
            montarDLLsCertificadosDigitais();
        } catch (IOException ex) {
            System.err.println("Erro ao montar dlls: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    public static List<String> getDLLsCertificadosDigitais(String tipo) {
        return dll.get(tipo);
    }

    /**
     * LOGIN DA APLICAÇÃO
     */
    /**
     * Função responsável por carregar as Dlls dos Certificados Digitais. Caso o
     * Certificado Digital do usuário não esteja sendo reconhecido pela
     * aplicação, verificar se a respectiva Dll está adicionada a esta lista.
     * Caso não esteja, adicioná-la e enviar e-mail para
     * selo.tecnologia@tjmg.jus.br solicitando inclusão do certificado na lista
     * de certificados suportados pelo SISNOR WEB.
     *
     * @throws IOException
     */
    private static void montarDLLsCertificadosDigitais() throws IOException {

        // Se o arquivo começar com /, não é adicionado SYSTEMROOT/System32/
        // antes dele, isso é feito para resolver providers que não são 
        // colocados por padrão no System32
        List<String> dllWindows = new ArrayList<String>();
        dllWindows.add("Prodemge;aetcsss1.dll");
        dllWindows.add("A-Trust-a-sign;asignp11.dll");
        dllWindows.add("ACS-ACOS5_smartcards;acospkcs11.dll");
        dllWindows.add("AET-Rainbow_iKey_3000_series;aetpkss1.dll");
        dllWindows.add("ASign-premium_cards;psepkcs11.dll");
        dllWindows.add("ActivCard_cards;acpkcs.dll");
        dllWindows.add("ActivClient;acpkcs211.dll");
        dllWindows.add("Aladdin-eToken_PRO;etpkcs11.dll");
        dllWindows.add("Aladdin-eToken_R2;etpkcs11.dll");
        dllWindows.add("Algorithmic-Research_MiniKey;sadaptor.dll");
        dllWindows.add("Aloaha-Smart_Card_Connector;aloaha_pkcs11.dll");
        dllWindows.add("Athena-Athena_Smartcard_System_ASE_Card;asepkcs.dll");
        dllWindows.add("Belgian-Government-Belgian_Electronic_Identity_Card;PKCS11.dll");
        dllWindows.add("Charismathics;cmP11.dll");
        dllWindows.add("Chrysalis-LUNA;cryst201.dll");
        dllWindows.add("Chrysalis;cryst32.dll");
        dllWindows.add("DallasSemiconductors-iButton;dspkcs.dll");
        dllWindows.add("Datakey;dkck201.dll");
        dllWindows.add("Datakey;pkcs201n.dll");
        dllWindows.add("Datakey_CIP;dkck201.dll");
        dllWindows.add("Datakey_iKey;dkck232.dll");
        dllWindows.add("Eracom;cryptoki.dll");
        dllWindows.add("Estonian_Government_Estonian_Electronic_Identity_Card;opensc-pkcs11.dll");
        dllWindows.add("Eutron-Crypto_Identity;sadaptor.dll");
        dllWindows.add("Feitain_technologys_Co_Ltd-ePass_1000;EP1PK111.DLL");
        dllWindows.add("Feitain_technologys_Co_Ltd-ePass_2000;ep2pk11.dll");
        dllWindows.add("Feitain_technologys_Co_Ltd-ePass_3000;ngp11v211.dll");
        dllWindows.add("Feitain_technologys_Co_Ltd-ePass_3003;ShuttleCsp11_3003.dll");
        dllWindows.add("Feitain_technologys_Co_Ltd_ePass_2000_FT11;ngp11v211.dll");
        dllWindows.add("Feitain_technologys_Co_Ltd_ePass_2003;eps2003csp11.dll");
        dllWindows.add("Fortezza_Module;fort32.dll");
        dllWindows.add("GemPlus_GemSoft;w32pk2ig.dll");
        dllWindows.add("GemSafe;gclib.dll");
        dllWindows.add("GemSafe alternativo 1;pk2priv.dll");
        dllWindows.add("GemSafe alternativo 2;/Arquivos de programas/Gemplus/GemSafe Libraries/BIN/gclib.dll");
        dllWindows.add("GemSafe alternativo 3;/Program Files/Gemplus/GemSafe Libraries/BIN/gclib.dll");
        dllWindows.add("Gemplus;gclib.dll");
        dllWindows.add("Gemplus;pk2priv.dll");
        dllWindows.add("IBM-IBM;cryptoki.dll");
        dllWindows.add("IBM-IBM_4758;cryptoki.dll");
        dllWindows.add("IBM-IBM_Digital_Signature_for_the_Internet_DSI_for_MFC_cards;CccSigIT.dll");
        dllWindows.add("IBM-IBM_Embededded_Security_Subsystem;csspkcs11.dll");
        dllWindows.add("IBM-IBM_Netfinity_PSG_Chip1;ibmpkcss.dll");
        dllWindows.add("IBM-IBM_SecureWay_Smartcard;w32pk2ig.dll");
        dllWindows.add("ID2;id2cbox.dll");
        dllWindows.add("MozillaNetscape_crypto_module;softokn3.dll");
        dllWindows.add("Nexus;nxpkcs11.dll");
        dllWindows.add("Oberthur_AuthentIC;AuCryptoki2-0.dll");
        dllWindows.add("OpenSC;opensc-pkcs11.dll");
        dllWindows.add("Orga_Micardo;micardoPKCS11.dll");
        dllWindows.add("Rainbow-CryptoSwiftAccelerator;Cryptoki22.dll");
        dllWindows.add("Rainbow-CryptoSwift_HSM;iveacryptoki.dll");
        dllWindows.add("Rainbow-Ikey1000;cryptoki22.dll");
        dllWindows.add("Rainbow-Key2000series_and_for_DataKey_cards;dkck201.dll");
        dllWindows.add("Rainbow-iKey_1000_1032;k1pk112.dll");
        dllWindows.add("Rainbow-iKey_2000_2032;dkck232.dll");
        dllWindows.add("Rainbow-iKey_2032;dkck201.dll");
        dllWindows.add("SCW_PKCS_3GI_3-G_International;3gp11csp.dll");
        dllWindows.add("SMART_CARD_S2_SAGEM;aetsprov.dll");
        dllWindows.add("Safelayer-HSM;p11card.dll");
        dllWindows.add("Schlumberger-Cryptoflex_Cyberflex_Access;slbck.dll");
        dllWindows.add("Schlumberger_Cryptoflex;acpkcs.dll");
        dllWindows.add("SeTec-SeTokI_cards;SetTokI.dll");
        dllWindows.add("Siemens-HiPath_SIcurity_Card;siecap11.dll");
        dllWindows.add("Siemens-Some_Siemens_Card_OS_cards;eTpkcs11.dll");
        dllWindows.add("SmartTrust;smartp11.dll");
        dllWindows.add("TeleSec;pkcs11.dll");
        dllWindows.add("Utimaco-Cryptoki_for_SafeGuard;pkcs201n.dll");
        dllWindows.add("Watchdata;WDPKCS.dll");
        dllWindows.add("Watchdata alternativo;Watchdata/Watchdata Brazil CSP v1.0/WDPKCS.dll");
        dllWindows.add("nCipher-nFast_nShield;cknfast.dll");
        dllWindows.add("oberthur;OcsCryptoki.dll");
        dllWindows.add("SafeNet_eTCAPI;eTCAPI.dll																");
        dllWindows.add("SafeNet_eTOKCSP;eTOKCSP.dll");
        dllWindows.add("SafeNet_API64;iKeyAPI64.dll");
        dllWindows.add("SafeNet_2K64;iKey2K64.dll");
        dllWindows.add("SCR3xxx_Smart_Card_Reader;MCSCM.dll");
        dllWindows.add("Watchdata_alternativo2;WatchData/WatchdataICPCSPv1.0/WDPKCS.dll");
        dllWindows.add("Watchdata;WDPKC.dll");
        dll = new HashMap<String, List<String>>();
        dll.put(DLLS_WINDOWS, dllWindows);

        // TODO: adicionar dlls linux        
        dll.put(DLLS_LINUX, new ArrayList<String>());

        System.out.println((new StringBuilder()).append("Map das DLLs do Sistema: ").append(dll).toString());
    }

    public static KeyStore carregarKeyStoreDoToken() {
        boolean encontrado = false;
        for (String biblioteca : getDLLsCertificadosDigitais(DLLS_WINDOWS)) {
            if (encontrado) {
                break;
            }

            String name = biblioteca.split(";")[0];
            String libraryPath = "C:/windows/system32/" + biblioteca.split(";")[1];
            final StringBuilder tokenConfiguration = new StringBuilder();

            if (libraryExists(name, libraryPath)) {
                long[] slots = getSlotsArray(libraryPath);
                System.out.print(" Slots:  " + Arrays.toString(slots) + " para biblioteca: " + libraryPath);
                if (slots != null && slots.length > 0) {
                    for (Long slot : getSlotsArray(libraryPath)) {
                        tokenConfiguration.setLength(0);
                        tokenConfiguration.append("name=").append(name.replace(" ", "")).append("\n");
                        tokenConfiguration.append("library=").append(libraryPath).append("\n");
                        tokenConfiguration.append("slot=").append(slot).append("\n");
                        tokenConfiguration.append("disabledMechanisms= {\nCKM_SHA1_RSA_PKCS\n}");
                        System.out.println(name);
                        System.out.println(tokenConfiguration.toString());
                        try {
                            Provider pkcs11Provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(tokenConfiguration
                                    .toString().getBytes()));
                            Security.addProvider(pkcs11Provider);
                            tokenProvider = pkcs11Provider;

                            System.out.print("Token/SmartCard carregado: " + name);
                            encontrado = true;
                            break;
                        } catch (ProviderException e) {
                            System.out.print("Erro ao instanciar provider =  " + e.getMessage());
                        }
                    }
                }
            }
        }

        if (tokenProvider == null) {
            JOptionPane.showMessageDialog(null, "Nenhum token encontrado", "ERRO", JOptionPane.ERROR_MESSAGE);
            throw new RuntimeException("Nenhum token encontrado");
        }

        KeyStore tokenKeystore = null;
        try {
            tokenKeystore = KeyStore.getInstance("PKCS11", tokenProvider);
        } catch (KeyStoreException ex) {
            logger.log(Level.SEVERE, "Não foi possível abrir o token: " + ex.getMessage(), ex);
            throw new RuntimeException("Não foi possível abrir o token: " + ex.getMessage(), ex);
        }

        try {
            final JPasswordField passfield = new JPasswordField();
            JOptionPane.showOptionDialog(null, passfield, "Senha do token", JOptionPane.NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[]{"Ok", "Cancelar"}, "Ok");
            String pin = String.valueOf(passfield.getPassword());
            tokenKeystore.load(null, pin.toCharArray());
            return tokenKeystore;
        } catch (CertificateException | NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, "Não foi possível fazer login no token: " + ex.getMessage(), ex);
            throw new RuntimeException("Não foi possível fazer login no token: " + ex.getMessage(), ex);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, "Não foi possível fazer login no token - SENHA INCORRETA: " + ex.getMessage(), ex);
            throw new RuntimeException("Não foi possível fazer login no token - SENHA INCORRETA: " + ex.getMessage(), ex);
        }
    }

    public static String selecionarAlias(KeyStore tokenKeystore) {
        try {
            Enumeration<String> aliasesEnum = tokenKeystore.aliases();

            final JComboBox<String> combo = new JComboBox<>();
            while (aliasesEnum.hasMoreElements()) {
                String a = aliasesEnum.nextElement();
                combo.addItem(a);
            }
            JOptionPane.showOptionDialog(null, combo, "Escolha o certificado", JOptionPane.NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, new String[]{"Ok"}, "Ok");
            return combo.getModel().getSelectedItem().toString();

        } catch (KeyStoreException ex) {
            logger.log(Level.SEVERE, "Erro ao listar aliases: " + ex.getMessage(), ex);
            throw new RuntimeException(
                    "Erro ao listar aliases: " + ex.getMessage(), ex);
        }
    }

    public static X509Certificate getCertificado(KeyStore tokenKeystore, String alias) {
        try {
            return (X509Certificate) tokenKeystore.getCertificate(alias);

        } catch (KeyStoreException ex) {
            logger.log(Level.SEVERE, "Não foi possível obter o certificado do alias " + alias + ": " + ex.getMessage(), ex);
            throw new RuntimeException(
                    "Não foi possível obter o certificado do alias " + alias + ": " + ex.getMessage(), ex);
        }
    }

    /**
     * EXECUÇÃO
     */
    public static PrivateKey getChavePrivada(KeyStore tokenKeystore, String alias) {
        try {
            if (tokenKeystore.isKeyEntry(alias)) {
                return (PrivateKey) tokenKeystore.getKey(alias, null);
            } else {
                throw new RuntimeException("Não existe o alias " + alias + " no KeyStore");

            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
            logger.log(Level.SEVERE, "Erro ao obter chave privada: " + ex.getMessage(), ex);
            throw new RuntimeException(
                    "Erro ao obter chave privada: " + ex.getMessage(), ex);
        }
    }

    public static PublicKey getChavePublicaTJMG() {
        if (chavePublicaTJMG == null) {
            try (InputStream is = CifradorDeAtosPraticados.class.getResourceAsStream(CAMINHO_CHAVE_PUBLICA_TJMG)) {
                CertificateFactory x509CertFact = CertificateFactory.getInstance("X.509");
                Certificate cert = x509CertFact.generateCertificate(is);
                chavePublicaTJMG = cert.getPublicKey();
            } catch (CertificateException | IOException ex) {
                logger.log(Level.SEVERE, "Erro ao obter arquivo do certificado do TJMG: " + ex.getMessage(), ex);
                throw new RuntimeException("Erro ao obter arquivo do certificado do TJMG: " + ex.getMessage(), ex);
            }
        }
        return chavePublicaTJMG;
    }

    public static String codificarEmBase64(String texto) {
        try {
            return Base64.encodeBase64String(texto.getBytes("UTF-8"));

        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, "Não foi possível obter bytes em UTF-8: " + ex.getMessage(), ex);
            throw new RuntimeException(
                    "Não foi possível obter bytes em UTF-8: " + ex.getMessage(), ex);
        }
    }

    /**
     * Certificado pode ser null
     *
     * @param xml documento xml
     * @param chavePublica chave pública de criptografia
     * @return xml cifrado
     */
    public static byte[] cifrarXml(byte[] xml, PublicKey chavePublica) {

        try {

            if (xml == null) {
                throw new IllegalArgumentException("xml não pode ser nulo");
            }
            if (chavePublica == null) {
                throw new IllegalArgumentException("chavePublica não pode ser nula");
            }

            if (!org.apache.xml.security.Init.isInitialized()) {
                org.apache.xml.security.Init.init();
            }
            Document documento = bytesToDocument(xml);
            Element elemento = (Element) documento.getElementsByTagName("Selos").item(0);

            // Generate a traffic key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            Key key = keygen.generateKey();

            XMLCipher cipher = null;

            cipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
            cipher.init(XMLCipher.WRAP_MODE, chavePublica);
            EncryptedKey encryptedKey = cipher.encryptKey(documento, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(documento);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);

            return documentToBytes(cipher.doFinal(documento, elemento));

        } catch (Exception ex) {
            logger.log(Level.SEVERE, "Erro ao cifrar arquivo: " + ex.getMessage(), ex);
            throw new RuntimeException("Erro ao cifrar arquivo: " + ex.getMessage(), ex);
        }
    }

    public static Document carregarDocumento(InputStream is) {
        try {
            return bytesToDocument(IOUtils.toByteArray(is));
        } catch (IOException ex) {
            logger.log(Level.SEVERE, "Erro ao abrir inputStream: " + ex.getMessage(), ex);
            throw new RuntimeException(
                    "Erro ao abrir inputStream: " + ex.getMessage(), ex);
        }
    }

    public static Document bytesToDocument(byte[] xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new ByteArrayInputStream(xml));

        } catch (ParserConfigurationException | SAXException | IOException ex) {
            logger.log(Level.SEVERE, "Erro ao converter para Document: " + ex.getMessage(), ex);
            throw new RuntimeException(
                    "Erro ao converter para Document: " + ex.getMessage(), ex);
        }
    }

    public static byte[] documentToBytes(Document documento) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            StreamResult streamResult = new StreamResult(bos);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            DOMSource domSource = new DOMSource(documento);
            transformer.transform(domSource, streamResult);
            return bos.toByteArray();
        } catch (TransformerException ex) {
            logger.log(Level.SEVERE, "Erro ao transformar documento em byte[]: " + ex.getMessage(), ex);
            throw new RuntimeException("Erro ao transformar documento em byte[]: " + ex.getMessage(), ex);
        }
    }

    public static long[] getSlotsArray(String libraryName) {
        try {
            CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
            initArgs.flags = CKF_OS_LOCKING_OK;
            PKCS11 p11 = PKCS11.getInstance(libraryName, "C_GetFunctionList", initArgs, false);
            return p11.C_GetSlotList(true);
        } catch (Throwable t) {
            System.err.println(t.toString());
            return null;
        }
    }

    public static boolean libraryExists(String name, String libraryPath) {
        File libraryFile = new File(libraryPath);
        if (libraryFile.exists()) {

            System.out.println((new StringBuilder()).append("Arquivo ").append(libraryPath).append(" existe.")
                    .toString());

            return true;
        }

        System.out.println((new StringBuilder()).append("Biblioteca do Token/SmartCard ").append(name)
                .append(" n\343o foi encontrada: ").append(libraryPath).toString());

        return false;
    }
}
