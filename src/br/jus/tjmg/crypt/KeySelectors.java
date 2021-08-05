package br.jus.tjmg.crypt;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.crypto.SecretKey;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.keyinfo.*;

/**
 * This is a class which supplies several KeySelector implementations
 *
 * @author Sean Mullan
 * @author Valerie Peng
 */
public class KeySelectors {

    /**
     * KeySelector which would always return the secret key specified in its
     * constructor.
     */
    public static class SecretKeySelector extends KeySelector {

        private final SecretKey key;

        public SecretKeySelector(byte[] bytes) {
            key = wrapBytes(bytes);
        }

        public SecretKeySelector(SecretKey key) {
            this.key = key;
        }

        @Override
        public KeySelectorResult select(KeyInfo ki,
                KeySelector.Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context)
                throws KeySelectorException {
            return new SimpleKSResult(key);
        }

        private SecretKey wrapBytes(final byte[] bytes) {
            return new SecretKey() {
                private static final long serialVersionUID = 3457835482691931082L;

                @Override
                public String getFormat() {
                    return "RAW";
                }

                @Override
                public String getAlgorithm() {
                    return "Secret key";
                }

                @Override
                public byte[] getEncoded() {
                    return bytes.clone();
                }
            };
        }
    }

    /**
     * KeySelector which would retrieve the X509Certificate out of the KeyInfo
     * element and return the public key. NOTE: If there is an X509CRL in the
     * KeyInfo element, then revoked certificate will be ignored.
     */
    public static class RawX509KeySelector extends KeySelector {

        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                KeySelector.Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context)
                throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            // search for X509Data in keyinfo
            Iterator<?> iter = keyInfo.getContent().iterator();
            while (iter.hasNext()) {
                XMLStructure kiType = (XMLStructure) iter.next();
                if (kiType instanceof X509Data) {
                    X509Data xd = (X509Data) kiType;
                    Object[] entries = xd.getContent().toArray();
                    X509CRL crl = null;
                    // Looking for CRL before finding certificates
                    for (int i = 0; (i < entries.length && crl == null); i++) {
                        if (entries[i] instanceof X509CRL) {
                            crl = (X509CRL) entries[i];
                        }
                    }
                    Iterator<?> xi = xd.getContent().iterator();
                    while (xi.hasNext()) {
                        Object o = xi.next();
                        // skip non-X509Certificate entries
                        if (o instanceof X509Certificate) {
                            if ((purpose != KeySelector.Purpose.VERIFY)
                                    && (crl != null)
                                    && crl.isRevoked((X509Certificate) o)) {
                            } else {
                                return new SimpleKSResult(((X509Certificate) o).getPublicKey());
                            }
                        }
                    }
                }
            }
            throw new KeySelectorException("No X509Certificate found!");
        }
    }

    /**
     * KeySelector which would retrieve the public key out of the KeyValue
     * element and return it. NOTE: If the key algorithm doesn't match signature
     * algorithm, then the public key will be ignored.
     */
    public static class KeyValueKeySelector extends KeySelector {

        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                KeySelector.Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context)
                throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            @SuppressWarnings("unchecked")
            List<XMLStructure> list = keyInfo.getContent();

            for (XMLStructure xmlStructure : list) {
                if (xmlStructure instanceof KeyValue) {
                    PublicKey pk = null;
                    try {
                        pk = ((KeyValue) xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    return new SimpleKSResult(pk);
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }
    }

    /**
     * KeySelector which would perform special lookup as documented by the
     * ie/baltimore/merlin-examples testcases and return the matching public
     * key.
     */
    public static class CollectionKeySelector extends KeySelector {

        private static final int MATCH_SUBJECT = 0;
        private static final int MATCH_ISSUER = 1;
        private static final int MATCH_SERIAL = 2;
        private static final int MATCH_SUBJECT_KEY_ID = 3;
        private static final int MATCH_CERTIFICATE = 4;
        private CertificateFactory certFac;
        private final File certDir;
        private List<X509Certificate> certs;

        public CollectionKeySelector(File dir) {
            certDir = dir;
            try {
                certFac = CertificateFactory.getInstance("X509");
            } catch (CertificateException ex) {
                // not going to happen
            }
            certs = new ArrayList<>();
            File[] files = new File(certDir, "certs").listFiles();
            for (File file : files) {
                try (FileInputStream is = new FileInputStream(file)) {
                    certs.add((X509Certificate) certFac.generateCertificate(is));
                } catch (Exception ex) {
                    // ignore non-cert files
                }
            }

        }

        public List<X509Certificate> match(
                int matchType, Object value, List<X509Certificate> pool) {
            List<X509Certificate> matchResult = new ArrayList<>();

            for (X509Certificate c : pool) {

                switch (matchType) {
                    case MATCH_SUBJECT:
                        Principal p1 = new javax.security.auth.x500.X500Principal((String) value);
                        if (c.getSubjectX500Principal().equals(p1)) {
                            matchResult.add(c);
                        }
                        break;
                    case MATCH_ISSUER:
                        Principal p2 = new javax.security.auth.x500.X500Principal((String) value);
                        if (c.getIssuerX500Principal().equals(p2)) {
                            matchResult.add(c);
                        }
                        break;
                    case MATCH_SERIAL:
                        if (c.getSerialNumber().equals(value)) {
                            matchResult.add(c);
                        }

                        break;
                    case MATCH_SUBJECT_KEY_ID:
                        byte[] extension = c.getExtensionValue("2.5.29.14");
                        if (extension != null) {
                            byte extVal[] = new byte[extension.length - 4];
                            System.arraycopy(extension, 4, extVal, 0, extVal.length);

                            if (Arrays.equals(extVal, (byte[]) value)) {
                                matchResult.add(c);
                            }
                        }
                        break;
                    case MATCH_CERTIFICATE:
                        if (c.equals(value)) {
                            matchResult.add(c);
                        }
                        break;
                }
            }
            return matchResult;
        }

        @Override
        public KeySelectorResult select(KeyInfo keyInfo,
                KeySelector.Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context)
                throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            Iterator<?> iter = keyInfo.getContent().iterator();
            while (iter.hasNext()) {
                XMLStructure xmlStructure = (XMLStructure) iter.next();
                try {
                    if (xmlStructure instanceof KeyName) {
                        String name = ((KeyName) xmlStructure).getName();
                        PublicKey pk = null;
                        try {
                            // Lookup the public key using the key name 'Xxx', 
                            // i.e. the public key is in "certs/xxx.crt".
                            File certFile = new File(new File(certDir, "certs"),
                                    name.toLowerCase() + ".crt");
                            try (FileInputStream is = new FileInputStream(certFile)) {
                                X509Certificate cert = (X509Certificate) certFac.generateCertificate(is);
                                pk = cert.getPublicKey();
                            }
                        } catch (FileNotFoundException e) {
                            // assume KeyName contains subject DN and search
                            // collection of certs for match
                            List<X509Certificate> result = match(MATCH_SUBJECT, name, certs);                            
                            if (result == null || result.size() != 1) {
                                throw new KeySelectorException((result == null || result.isEmpty()? "No" : "More than one" )
                                        + " match found");
                            } else {
                                pk = result.get(0).getPublicKey();
                            }
                        }
                        return new SimpleKSResult(pk);
                    } else if (xmlStructure instanceof RetrievalMethod) {
                        // Lookup the public key using the retrievel method.
                        // NOTE: only X509Certificate type is supported.
                        RetrievalMethod rm = (RetrievalMethod) xmlStructure;
                        String type = rm.getType();
                        if (type.equals(X509Data.RAW_X509_CERTIFICATE_TYPE)) {
                            String uri = rm.getURI();
                            try (FileInputStream is = new FileInputStream(new File(certDir, uri))) {
                                X509Certificate cert = (X509Certificate) certFac.generateCertificate(is);
                                return new SimpleKSResult(cert.getPublicKey());
                            }
                        } else {
                            throw new KeySelectorException("Unsupported RetrievalMethod type");
                        }
                    } else if (xmlStructure instanceof X509Data) {
                        List<?> content = ((X509Data) xmlStructure).getContent();
                        int size = content.size();
                        List<X509Certificate> result = null;
                        // Lookup the public key using the information 
                        // specified in X509Data element, i.e. searching
                        // over the collection of certificate files under
                        // "certs" subdirectory and return those match.
                        for (int k = 0; k < size; k++) {
                            Object obj = content.get(k);
                            if (obj instanceof String) {
                                result = match(MATCH_SUBJECT, obj, certs);
                            } else if (obj instanceof byte[]) {
                                result = match(MATCH_SUBJECT_KEY_ID, obj, certs);
                            } else if (obj instanceof X509Certificate) {
                                result = match(MATCH_CERTIFICATE, obj, certs);
                            } else if (obj instanceof X509IssuerSerial) {
                                X509IssuerSerial is = (X509IssuerSerial) obj;
                                result = match(MATCH_SERIAL,
                                        is.getSerialNumber(), certs);
                                result = match(MATCH_ISSUER,
                                        is.getIssuerName(), result);
                            } else {
                                throw new KeySelectorException("Unsupported X509Data: " + obj);
                            }
                        }                        
                        if (result == null || result.size() != 1) {
                            throw new KeySelectorException((result == null || result.isEmpty()? "No" : "More than one" )
                                        + " match found");
                        } else {
                            return new SimpleKSResult(result.get(0).getPublicKey());
                        }
                    }
                } catch (IOException | CertificateException | KeySelectorException ex) {
                    throw new KeySelectorException(ex);
                }
            }
            throw new KeySelectorException("No matching key found!");
        }
    }

    public static class ByteUtil {

        private static final String mapping = "0123456789ABCDEF";
        private static final int numBytesPerRow = 6;

        private static String getHex(byte value) {
            int low = value & 0x0f;
            int high = ((value >> 4) & 0x0f);
            char[] res = new char[2];
            res[0] = mapping.charAt(high);
            res[1] = mapping.charAt(low);
            return new String(res);
        }

        public static String dumpArray(byte[] in) {
            int numDumped = 0;
            StringBuilder buf = new StringBuilder(512);
            buf.append("{");
            for (int i = 0; i < (in.length / numBytesPerRow); i++) {
                for (int j = 0; j < (numBytesPerRow); j++) {
                    buf.append("(byte)0x").append(getHex(in[i * numBytesPerRow + j])).append(", ");
                }
                numDumped += numBytesPerRow;
            }
            while (numDumped < in.length) {
                buf.append("(byte)0x").append(getHex(in[numDumped])).append(" ");
                numDumped += 1;
            }
            buf.append("}");
            return buf.toString();
        }

        private ByteUtil() {
        }
    }

    private static class SimpleKSResult implements KeySelectorResult {

        private final Key key;

        SimpleKSResult(Key key) {
            this.key = key;
        }

        @Override
        public Key getKey() {
            return key;
        }
    }
}
