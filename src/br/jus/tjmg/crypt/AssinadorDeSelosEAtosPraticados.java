package br.jus.tjmg.crypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.DocumentTraversal;
import org.w3c.dom.traversal.NodeFilter;
import org.w3c.dom.traversal.NodeIterator;
import org.xml.sax.SAXException;

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
public class AssinadorDeSelosEAtosPraticados {

    private static final String MECHANISM = "DOM";
    private static final String PROVIDER_NAME = System.getProperty("jsr105Provider",
            "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
    private static XMLSignatureFactory fac;

    static {
        try {
            fac = XMLSignatureFactory.getInstance(MECHANISM, (Provider) Class.forName(PROVIDER_NAME).newInstance());
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException ex) {
            Logger.getLogger(SeloCryptUtil.class.getName()).log(Level.SEVERE, "Erro ao carregar XMLSignatureFactory: " + ex.getMessage(), ex);
        }
    }

    private AssinadorDeSelosEAtosPraticados() {
    }

    private static javax.xml.crypto.dsig.keyinfo.KeyInfo criaTagKeyInfo(KeyStore ks, String alias) throws KeyStoreException,
            InstantiationException, IllegalAccessException, ClassNotFoundException {
        X509Certificate cert = SeloCryptUtil.getCertificado(ks, alias);
        List<X509Certificate> x509Content = new ArrayList<>();
        x509Content.add(cert);
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        javax.xml.crypto.dsig.keyinfo.X509Data xd = kif.newX509Data(x509Content);
        return kif.newKeyInfo(Collections.singletonList(xd));
    }

    private static SignedInfo criaTagSignedInfo() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ArrayList<javax.xml.crypto.dsig.Transform> transform = new ArrayList<>();
        javax.xml.crypto.dsig.spec.TransformParameterSpec tps = null;
        javax.xml.crypto.dsig.Transform envelopedTransform = fac.newTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature", tps);
        javax.xml.crypto.dsig.Transform c14NTransform = fac.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", tps);
        transform.add(envelopedTransform);
        transform.add(c14NTransform);
        javax.xml.crypto.dsig.DigestMethod digestMethod = fac.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null);
        javax.xml.crypto.dsig.CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                (C14NMethodParameterSpec) null);
        javax.xml.crypto.dsig.SignatureMethod signatureMethod = //
                fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null);
        javax.xml.crypto.dsig.Reference ref = fac.newReference("", digestMethod, transform, null, null);
        return fac.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(ref));
    }

    public static String assinarDocumentoXml(Document doc, KeyStore keyStore, String alias) {
        if (!org.apache.xml.security.Init.isInitialized()) {
            org.apache.xml.security.Init.init();
        }
        try {
            SignedInfo si = criaTagSignedInfo();
            X509Certificate cert = SeloCryptUtil.getCertificado(keyStore, alias);
            javax.xml.crypto.dsig.keyinfo.KeyInfo ki = criaTagKeyInfo(keyStore, alias);

            DOMSignContext dsc = new DOMSignContext(SeloCryptUtil.getChavePrivada(keyStore, alias), doc.getDocumentElement());
            XMLSignature signature = fac.newXMLSignature(si, ki);
            signature.sign(dsc);

            return asConteudoXml(doc);

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | KeyStoreException | InstantiationException | IllegalAccessException | ClassNotFoundException | MarshalException | XMLSignatureException | InvalidCanonicalizerException | IOException | CanonicalizationException ex) {
            Logger.getLogger(SeloCryptUtil.class.getName()).log(Level.SEVERE, "Erro ao assinar arquivo: " + ex.getMessage(), ex);
            throw new RuntimeException("Erro ao assinar arquivo: " + ex.getMessage(), ex);
        }
    }

    /**
     * Utiliza a mesma verificação que a aplicação está utilizando atualmente
     * (22/05/2014).
     *
     * @param inputStream inputStream do xml
     * @return
     */
    public static boolean verificarAssinaturaDocumentoXml(final InputStream inputStream) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
//            inputStream = new FileInputStream("4201.xml");
            dbf.setNamespaceAware(true);
            dbf.setValidating(false);
            Document doc;

            DocumentBuilder builder = dbf.newDocumentBuilder();

            doc = builder.parse(inputStream);
            NodeIterator ni = ((DocumentTraversal) doc).createNodeIterator(
                    doc.getDocumentElement(), NodeFilter.SHOW_ELEMENT, null, false);
            Node node;
            for (node = ni.nextNode(); node != null; node = ni.nextNode()) {
                if ("Signature".equals(node.getLocalName()) || "Signature".equals(node.getNodeName()) || node.getNodeName().endsWith(":Signature")) {
                    break;
                }
            }
            // caso nao encontre um elemento de assinatura dentro do xml envio erro.
            if (node == null) {
                Logger.getLogger(AssinadorDeSelosEAtosPraticados.class.getName()).log(Level.SEVERE, "Não foi encontrado o elemento Signature no xml");
                throw new RuntimeException("Não foi encontrado o elemento Signature no xml");
            }
            // carrego um factory de assinatura com provider especifico XMLDSigRI
            DOMValidateContext valContext = new DOMValidateContext(new KeySelectors.RawX509KeySelector(), node);
            fac = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
            valContext.setBaseURI(node.getBaseURI());

            // valido a assinatura
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            return signature.validate(valContext);
        } catch (SAXException | IOException | ParserConfigurationException | MarshalException | XMLSignatureException ex) {
            Logger.getLogger(AssinadorDeSelosEAtosPraticados.class.getName()).log(Level.SEVERE, "Erro ao validar assinatura: " + ex.getMessage(), ex);
            throw new RuntimeException("Erro ao validar assinatura: " + ex.getMessage(), ex);
        }

    }

    private static String asConteudoXml(final Node n) throws InvalidCanonicalizerException, IOException, CanonicalizationException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Canonicalizer c14n = null;
        byte[] serBytes = null;
        c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        serBytes = c14n.canonicalizeSubtree(n);
        baos.write(serBytes);
        baos.close();
        return baos.toString("UTF-8");
    }
}
