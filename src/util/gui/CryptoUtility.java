package util.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;

import org.bouncycastle.util.encoders.Base64;

import util.crypto.CryptoEncDe;

public class CryptoUtility extends JPanel {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public CryptoUtility() {
		super(new BorderLayout());

		// Create a file chooser
		final JFileChooser fc = new JFileChooser();

		final JPanel panel = new JPanel(new GridLayout(1, 1));

		JPanel filePanel = new JPanel();

		JPanel keyStorePanel = new JPanel(new GridLayout(3, 4, 26, 4));

		keyStorePanel.add(new JLabel("Keystore Password"));

		final JPasswordField keystorePasswordField = new JPasswordField(14);

		keyStorePanel.add(keystorePasswordField);

		keyStorePanel.add(new JLabel("Key Password"));

		JPasswordField keyPasswordField = new JPasswordField(14);
		keyStorePanel.add(keyPasswordField);

		keyStorePanel.add(new JLabel("Key Name/Alias"));

		final JComboBox keyNameField = new JComboBox();

		keyStorePanel.add(keyNameField);

		keyStorePanel.add(new JLabel("Store Type"));

		final JComboBox storeTypeList = new JComboBox(java.security.Security.getAlgorithms("KeyStore").toArray());

		keyStorePanel.add(storeTypeList);

		keyStorePanel.add(new JLabel("Keystore File"));

		final JTextField keyStoreFileField = new JTextField(14);
		keyStorePanel.add(keyStoreFileField);

		JButton chooseKeystoreButton = new JButton("Choose Keystore");
		keyStorePanel.add(chooseKeystoreButton);
		chooseKeystoreButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				int returnVal = fc.showOpenDialog(panel);

				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();

					if (!file.getAbsolutePath().equals(keyStoreFileField.getText()))
						keyNameField.removeAllItems();

					keyStoreFileField.setText(file.getAbsolutePath());

				}

			}
		});

		JButton loadAliasesButton = new JButton("Load Aliases");
		keyStorePanel.add(loadAliasesButton);
		loadAliasesButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent actionEvent) {

				try {
					KeyStore keystore = KeyStore.getInstance(storeTypeList.getSelectedItem().toString());
					FileInputStream fileInputStream = new FileInputStream(new File(keyStoreFileField.getText()));

					keystore.load(fileInputStream, keystorePasswordField.getPassword());
					fileInputStream.close();

					DefaultComboBoxModel model = new DefaultComboBoxModel();

					Enumeration<String> keyAliases = keystore.aliases();

					while (keyAliases.hasMoreElements()) {
						String keyAlias = (String) keyAliases.nextElement();
						model.addElement(keyAlias);
					}

					keyNameField.setModel(model);

				} catch (Exception ex) {
					// TODO Auto-generated catch block
					ex.printStackTrace();
					CryptoUtility.throwExceptionDialog((Component) actionEvent.getSource(), ex);
				}
			}
		});

		keyStorePanel.setBorder(BorderFactory.createTitledBorder("Java Keystore Attirbutes"));

		JPanel cryptoPanel = new JPanel(new GridLayout(1, 2));

		cryptoPanel.setBorder(BorderFactory.createTitledBorder("Encrypted/Decrypted Text"));

		JPanel plainTextPanel = new JPanel(new BorderLayout());
		JPanel encryptedTextPanel = new JPanel(new BorderLayout());

		plainTextPanel.setBorder(BorderFactory.createTitledBorder("Plain Text"));
		encryptedTextPanel.setBorder(BorderFactory.createTitledBorder("Encrypted Text"));

		JTextArea plainTextArea = new JTextArea(18, 50);
		plainTextPanel.add(new JScrollPane(plainTextArea));

		JTextArea encryptedTextArea = new JTextArea(18, 50);
		encryptedTextPanel.add(new JScrollPane(encryptedTextArea));

		cryptoPanel.add(plainTextPanel);
		cryptoPanel.add(encryptedTextPanel);

		JPanel buttonPanel = new JPanel();

		JButton encryptButton = new JButton("Encrypt");
		buttonPanel.add(encryptButton);
		encryptButton.addActionListener(new CryptoActionListener(keyStoreFileField, storeTypeList,
				keystorePasswordField, keyNameField, keyPasswordField, plainTextArea, encryptedTextArea, true));

		JButton decryptButton = new JButton("Decrypt");
		buttonPanel.add(decryptButton);
		decryptButton.addActionListener(new CryptoActionListener(keyStoreFileField, storeTypeList,
				keystorePasswordField, keyNameField, keyPasswordField, encryptedTextArea, plainTextArea, false));

		filePanel.add(keyStorePanel);
		filePanel.add(cryptoPanel);
		filePanel.add(buttonPanel);

		panel.add(filePanel);

		setPreferredSize(new Dimension(1200, 550));
		add(panel, BorderLayout.CENTER);

	}

	/**
	 * Create the GUI and show it. For thread safety, this method should be
	 * invoked from the event-dispatching thread.
	 */
	private static void createAndShowGUI() {
		// Create and set up the window.
		JFrame frame = new JFrame("Crypto Utility");
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		CryptoUtility demo = new CryptoUtility();
		demo.setOpaque(true); // content panes must be opaque
		frame.setContentPane(demo);

		// Display the window.
		frame.pack();
		frame.setVisible(true);
	}

	public static void main(String[] args) {
		// Schedule a job for the event-dispatching thread:
		// creating and showing this application's GUI.

		javax.swing.SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				// Turn off metal's use of bold fonts
				UIManager.put("swing.boldMetal", Boolean.FALSE);
				createAndShowGUI();
			}
		});

	}

	public static void throwExceptionDialog(Component c, Exception e) {
		JOptionPane.showMessageDialog(c.getParent(), e.getMessage(), e.getClass().getName(), JOptionPane.ERROR_MESSAGE);
	}
}

class CryptoActionListener implements ActionListener {

	private JComboBox storeTypeList;
	private JTextField keyStoreFileField;
	private JPasswordField keystorePasswordField;
	private JComboBox keyNameField;
	private JPasswordField keyPasswordField;
	private CryptoEncDe cryptoEncDe;
	private JTextArea sourceTextArea;
	private JTextArea destinationTextArea;
	boolean encrypt = true;

	CryptoActionListener(JTextField keyStoreFileField, JComboBox storeTypeList, JPasswordField keystorePasswordField,
			JComboBox keyNameField, JPasswordField keyPasswordField, JTextArea sourceTextArea,
			JTextArea destinationTextArea, boolean encrypt) {

		this.keyStoreFileField = keyStoreFileField;
		this.storeTypeList = storeTypeList;

		this.keystorePasswordField = keystorePasswordField;
		this.keyNameField = keyNameField;
		this.keyPasswordField = keyPasswordField;

		this.cryptoEncDe = new CryptoEncDe();

		this.sourceTextArea = sourceTextArea;
		this.destinationTextArea = destinationTextArea;
		this.encrypt = encrypt;
	}

	@Override
	public void actionPerformed(ActionEvent actionEvent) {

		try {
			cryptoEncDe.init(storeTypeList.getSelectedItem().toString(), new File(keyStoreFileField.getText()),
					keystorePasswordField.getPassword());

			String destinationText = "";

			Object keyName = keyNameField.getSelectedItem();

			if (keyName == null)
				throw new UnrecoverableKeyException("Please load the aliases/key names");

			if (Cipher.getMaxAllowedKeyLength("AES") <= 128) {
				throw new Exception(
						"This applciation needs Unlimited Strength Jurisdiction Policy Files. \n"
								+ "For more information please check for "
								+ "\"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files\" in the Java SE downloads section");
			}

			if (encrypt)
				destinationText = new String(Base64.encode(cryptoEncDe.encrypt(keyName.toString(), keyPasswordField
						.getPassword(), sourceTextArea.getText())), "UTF-8");
			else
				destinationText = new String(cryptoEncDe.decrypt(keyName.toString(), keyPasswordField.getPassword(),
						Base64.decode(sourceTextArea.getText())), "UTF-8");

			destinationTextArea.setText(destinationText);

		} catch (NullPointerException npe) {
			/*
			 * TODO This should not be happening this way, possible because of
			 * the hard-coded Cipher instance transformation
			 * "AES/ECB/PKCS5Padding" @
			 * <code>util.crypto.CryptoEncDe.[encrypt|decrypt]</code>
			 */
			CryptoUtility.throwExceptionDialog((Component) actionEvent.getSource(), new Exception(
					"Unknown Error Occurred"));
			npe.printStackTrace();
		} catch (Exception ex) {
			CryptoUtility.throwExceptionDialog((Component) actionEvent.getSource(), ex);
			ex.printStackTrace();
		}

	}

}