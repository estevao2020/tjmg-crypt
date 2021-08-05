/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package br.jus.tjmg.main;

import br.jus.tjmg.crypt.AssinadorDeSelosEAtosPraticados;
import br.jus.tjmg.crypt.CifradorDeAtosPraticados;
import br.jus.tjmg.crypt.SeloCryptUtil;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import org.apache.commons.io.FileUtils;
import org.w3c.dom.Document;

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
public class AssinadorEmLoteGUI {

    private final static Logger logger = Logger.getLogger(AssinadorEmLoteGUI.class.getName());
    private static final String PREF_B64 = "b64";
    private static final String PREF_XML = "xml";
    private static final String PREF_CRIPTOGRAFAR = "criptografar";
    private static final String PREF_DIR_ENTRADA = "dirEntrada";
    private static final String PREF_DIR_SAIDA = "dirSaida";

    public static void main(String[] args) {
        try {
            // Obt�m certificado digital do usu�rio logado
            KeyStore tokenStore = SeloCryptUtil.carregarKeyStoreDoToken();
            String alias = SeloCryptUtil.selecionarAlias(tokenStore);
            final X509Certificate cert = SeloCryptUtil.getCertificado(tokenStore, alias);

            // Obt�m prefer�ncias selecionadas pelo usu�rio em execu��o anterior
            Preferences prefs = Preferences.userNodeForPackage(AssinadorEmLoteGUI.class);

            /**
             * MONTAGEM DA TELA DA APLICA��O
             */
            // Define tela da aplica��o
            final JPanel panelOpcoes = new JPanel();
            panelOpcoes.setLayout(new BoxLayout(panelOpcoes, BoxLayout.Y_AXIS));

            // Acesso � exibi��o de informa��es do certificado
            JButton usoBtn = new JButton("Informa��es do certificado");
            usoBtn.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    exibirInformacoesUsoDoCertificado(panelOpcoes, cert);
                }
            });
            panelOpcoes.add(usoBtn);

            // Controle do diret�rio de entrada
            final JFileChooser dirEntradaChooser = montarDiretorioEntrada(panelOpcoes, prefs);

            // Controle do diret�rio de sa�da
            final JFileChooser dirSaidaChooser = montarDiretorioSaida(panelOpcoes, prefs);

            // Check box para defini��o de arquivos a serem gerados
            boolean b64 = prefs.getBoolean(PREF_B64, true);
            boolean xml = prefs.getBoolean(PREF_XML, true);
            boolean criptografar = prefs.getBoolean(PREF_CRIPTOGRAFAR, true);
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            JCheckBox b64Chk = new JCheckBox("Gerar base 64", b64);
            JCheckBox xmlChk = new JCheckBox("Gerar assinado", xml);
            JCheckBox criptografarChk = new JCheckBox("Gerar criptografado", criptografar);
            panelOpcoes.add(leftAlign(b64Chk, xmlChk, criptografarChk));

            /**
             * Inicia gera��o de novos arquivos e salva prefer�ncias do usu�rio
             * para execu��o futura
             */
            int gerar = JOptionPane.showConfirmDialog(null, panelOpcoes, "TJMG Crypt", JOptionPane.OK_CANCEL_OPTION);
            if (gerar != JOptionPane.OK_OPTION) {
                return;
            }
            File dirEntrada = dirEntradaChooser.getSelectedFile();
            File dirSaida = dirSaidaChooser.getSelectedFile();
            b64 = b64Chk.isSelected();
            xml = xmlChk.isSelected();
            criptografar = criptografarChk.isSelected();
            if (!dirEntrada.exists()) {
                logger.log(Level.SEVERE, "Diretorio de entrada ({0}) nao existe", dirEntrada.getAbsolutePath());
                return;
            }
            if (dirSaida.equals(dirEntrada)) {
                logger.log(Level.SEVERE, "Diretorio de saida n�o pode ser igual ao diret�rio de entrada");
            }
            if (dirSaida.exists() && !dirSaida.isDirectory()) {
                logger.log(Level.SEVERE, "Diretorio de saida ({0}) nao e um diretorio", dirSaida.getAbsolutePath());
                return;
            }
            prefs.putBoolean(PREF_B64, b64);
            prefs.putBoolean(PREF_XML, xml);
            prefs.putBoolean(PREF_CRIPTOGRAFAR, xml);
            prefs.put(PREF_DIR_ENTRADA, dirEntrada.getPath());
            prefs.put(PREF_DIR_SAIDA, dirSaida.getPath());

            /**
             * EXECU��O DA APLICA��O
             */
            // Percorre arquivos do diret�rio de entrada para realiza��o das opera��es desejadas
            for (File arquivo : FileUtils.listFiles(dirEntrada, new String[]{"xml"}, false)) {
                logger.log(Level.INFO, "Processando {0}... ", arquivo.getName());
                Document doc = SeloCryptUtil.carregarDocumento(new FileInputStream(arquivo));
                String xmlAssinado = AssinadorDeSelosEAtosPraticados.assinarDocumentoXml(doc, tokenStore, alias);

                if (xml) {
                    try {
                        File xmlSaida = new File(dirSaida, arquivo.getName().replaceAll("\\.xml$", "_assinado.xml"));
                        FileUtils.writeStringToFile(xmlSaida, xmlAssinado, "UTF-8");
                        Logger.getLogger(AssinadorEmLoteGUI.class.getName()).log(Level.INFO, "Documento xml salvo em {0}", xmlSaida.getAbsolutePath());
                    } catch (IOException ex) {
                        Logger.getLogger(AssinadorEmLoteGUI.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                if (b64) {
                    try {
                        File base64Saida = new File(dirSaida, arquivo.getName().replaceAll("\\.xml$", "_assinado.b64"));
                        FileUtils.writeStringToFile(base64Saida, SeloCryptUtil.codificarEmBase64(xmlAssinado));
                        Logger.getLogger(AssinadorEmLoteGUI.class.getName()).log(Level.INFO, "Documento em base64 salvo em {0}", base64Saida.getAbsolutePath());
                    } catch (IOException ex) {
                        Logger.getLogger(AssinadorEmLoteGUI.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                if (criptografar) {
                    try {
                        File arquivoCriptografado = new File(dirSaida, arquivo.getName().replaceAll("\\.xml$", "_criptografado.xml"));
                        String xmlCriptografado = CifradorDeAtosPraticados.cifrarComChavePublicaDoTJMG(xmlAssinado);
                        FileUtils.writeStringToFile(arquivoCriptografado, xmlCriptografado, "UTF-8");
                        Logger.getLogger(AssinadorEmLoteGUI.class.getName()).log(Level.INFO, "Documento criptografado salvo em {0}", arquivoCriptografado.getAbsolutePath());
                    } catch (IOException ex) {
                        Logger.getLogger(AssinadorEmLoteGUI.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        } catch (FileNotFoundException ex) {
            logger.log(Level.SEVERE, "Erro ao ler arquivo: " + ex.getLocalizedMessage(), ex);
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
            Logger.getLogger(AssinadorEmLoteGUI.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * M�TODOS AUXILIARES
     */
    private static Component leftAlign(JComponent... components) {
        Box b = Box.createHorizontalBox();
        for (JComponent comp : components) {
            b.add(comp);
        }
        b.add(Box.createHorizontalGlue());
        return b;
    }

    private static void exibirInformacoesUsoDoCertificado(JComponent pai, X509Certificate cert) {
        final StringBuilder informacoes = new StringBuilder("<html>");
        boolean[] keyUsage = cert.getKeyUsage();
        informacoes.append("<ul>");
        informacoes.append("<li>digitalSignature : ").append(keyUsage[0]).append("</li>");
        informacoes.append("<li>nonRepudiation: ").append(keyUsage[1]).append("</li>");
        informacoes.append("<li>keyEncipherment : ").append(keyUsage[2]).append("</li>");
        informacoes.append("<li>dataEncipherment : ").append(keyUsage[3]).append("</li>");
        informacoes.append("<li>Key agreement: ").append(keyUsage[4]).append("</li>");
        informacoes.append("<li>keyCertSign : ").append(keyUsage[5]).append("</li>");
        informacoes.append("<li>cRLSign: ").append(keyUsage[6]).append("</li>");
        informacoes.append("<li>encipherOnly: ").append(keyUsage[7]).append("</li>");
        informacoes.append("<li>decipherOnly: ").append(keyUsage[8]).append("</li>");
        informacoes.append("</ul>");
        informacoes.append("</html>");
        JPanel painel = new JPanel(new BorderLayout());
        painel.add(new JLabel("Informa��es"), BorderLayout.NORTH);
        painel.add(new JLabel(informacoes.toString()), BorderLayout.CENTER);
        JOptionPane.showMessageDialog(pai, painel);
    }

    private static JFileChooser montarDiretorioEntrada(final JComponent pai, Preferences prefs) {
        // Define valor inicial para dirEntrada
        File dirEntrada = new File(prefs.get(PREF_DIR_ENTRADA, "atos"));
        if (!dirEntrada.exists()) {
            dirEntrada = new File(System.getProperty("user.dir"));
        }
        final JLabel lblDirEntrada = new JLabel(dirEntrada.getAbsolutePath());

        // Define JFileChooser para permitir usu�rio selecionar diret�rio desejado
        final JFileChooser dirEntradaChooser = new JFileChooser() {
            private static final long serialVersionUID = 1L;

            @Override
            public void approveSelection() {
                if (getSelectedFile() == null || !getSelectedFile().exists() || !getSelectedFile().isDirectory()) {
                    JOptionPane.showMessageDialog(this, "Arquivo selecionado n�o � um diret�rio", "", JOptionPane.ERROR_MESSAGE);
                } else {
                    super.approveSelection();
                }
            }
        };
        dirEntradaChooser.setSelectedFile(dirEntrada);
        dirEntradaChooser.setCurrentDirectory(dirEntrada);
        dirEntradaChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        dirEntradaChooser.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (e.getActionCommand().equals(JFileChooser.APPROVE_SELECTION)) {
                    lblDirEntrada.setText(dirEntradaChooser.getSelectedFile().getAbsolutePath());
                    dirEntradaChooser.setCurrentDirectory(dirEntradaChooser.getSelectedFile());
                    ((Window) lblDirEntrada.getTopLevelAncestor()).pack();
                }
            }
        });

        // Adiciona label e comandos do diret�rio de entrada ao panel pai
        pai.add(leftAlign(new JLabel("<html><b>Diret�rio entrada:</b></html>")));
        JButton btnDirEntrada = new JButton("...");
        btnDirEntrada.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dirEntradaChooser.showOpenDialog(pai);
            }
        });
        pai.add(leftAlign(lblDirEntrada, btnDirEntrada));

        // Retorna JFileChooser
        return dirEntradaChooser;
    }

    private static JFileChooser montarDiretorioSaida(final JComponent pai, Preferences prefs) {
        // Define valor inicial para dirSaida
        File dirSaida = new File(prefs.get(PREF_DIR_SAIDA, "c:/atos_crypt"));
        dirSaida.mkdirs();
        final JLabel lblDirSaida = new JLabel(dirSaida.getAbsolutePath());

        // Define JFileChooser para permitir usu�rio selecionar diret�rio desejado
        final JFileChooser dirSaidaChooser = new JFileChooser();
        dirSaidaChooser.setSelectedFile(dirSaida);
        dirSaidaChooser.setCurrentDirectory(dirSaida);
        dirSaidaChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        dirSaidaChooser.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (e.getActionCommand().equals(JFileChooser.APPROVE_SELECTION)) {
                    lblDirSaida.setText(dirSaidaChooser.getSelectedFile().getAbsolutePath());
                    dirSaidaChooser.setCurrentDirectory(dirSaidaChooser.getSelectedFile());
                    ((Window) lblDirSaida.getTopLevelAncestor()).pack();
                }
            }
        });

        // Adiciona label e comandos do diret�rio de sa�da ao panel pai
        pai.add(leftAlign(new JLabel("<html><b>Diret�rio sa�da:</b></html>")));
        JButton btnDirSaida = new JButton("...");
        btnDirSaida.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dirSaidaChooser.showOpenDialog(pai);
            }
        });
        pai.add(leftAlign(lblDirSaida, btnDirSaida));

        // Retorna JFileChooser
        return dirSaidaChooser;
    }
}
