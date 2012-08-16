package util.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpringLayout;
import javax.swing.UIManager;

import org.bouncycastle.util.encoders.Base64;

import util.crypto.CryptoEncDe;

public class CryptoUtility extends JPanel {

	public CryptoUtility() {
		super(new BorderLayout());

		// Create a file chooser
		final JFileChooser fc = new JFileChooser();

		final JPanel panel = new JPanel(new GridLayout(1, 1));

		JPanel filePanel = new JPanel();

		JPanel keyStorePanel = new JPanel(new GridLayout(1, 8));

		keyStorePanel.add(new JLabel("Keystore Password"));

		JPasswordField keystorePasswordField = new JPasswordField();

		keyStorePanel.add(keystorePasswordField);

		keyStorePanel.add(new JLabel("Key Password"));

		JPasswordField keyPasswordField = new JPasswordField();
		keyStorePanel.add(keyPasswordField);

		keyStorePanel.add(new JLabel("Key Name"));

		final JTextField keyNameField = new JTextField();

		keyStorePanel.add(keyNameField);

		keyStorePanel.add(new JLabel("Keystore"));

		final JTextField keyStoreFileField = new JTextField();

		keyStorePanel.add(keyStoreFileField);

		JButton chooseKeystoreButton = new JButton("Choose Keystore");
		keyStorePanel.add(chooseKeystoreButton);
		chooseKeystoreButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				int returnVal = fc.showOpenDialog(panel);

				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					// This is where a real application would open the file.
					keyStoreFileField.setText(file.getAbsolutePath());
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

		JTextArea plainTextArea =  new JTextArea(18, 50);
		plainTextPanel.add(new JScrollPane(plainTextArea));

		
		JTextArea encryptedTextArea =  new JTextArea(18, 50);
		encryptedTextPanel.add(new JScrollPane(encryptedTextArea));

		cryptoPanel.add(plainTextPanel);
		cryptoPanel.add(encryptedTextPanel);

		JPanel buttonPanel = new JPanel();

		JButton encryptButton = new JButton("Encrypt");
		buttonPanel.add(encryptButton);
		encryptButton.addActionListener(new CryptoActionListener(keyStoreFileField,
				keystorePasswordField, keyNameField, keyPasswordField, plainTextArea,encryptedTextArea, true));

		JButton decryptButton = new JButton("Decrypt");
		buttonPanel.add(decryptButton);
		decryptButton.addActionListener(new CryptoActionListener(keyStoreFileField,
				keystorePasswordField, keyNameField, keyPasswordField,encryptedTextArea,plainTextArea, false));

		filePanel.add(keyStorePanel);
		filePanel.add(cryptoPanel);
		filePanel.add(buttonPanel);
		// new
		// JScrollPane(cryptoPanel,ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED));

		panel.add(filePanel);

		setPreferredSize(new Dimension(1200, 450));
		add(panel, BorderLayout.CENTER);

		// cryptoEncDe.init("jceks", new File(keyStoreFile), storePasswordChar);
	}

	/**
	 * Create the GUI and show it. For thread safety, this method should be
	 * invoked from the event-dispatching thread.
	 */
	private static void createAndShowGUI() {
		// Create and set up the window.
		JFrame frame = new JFrame("Crypto Utility");
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		// Create and set up the menu bar and content pane.
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
}

class CryptoActionListener implements ActionListener {

	private JTextField keyStoreFileField;
	private JPasswordField keystorePasswordField;
	private JTextField keyNameField;
	private JPasswordField keyPasswordField;
	private CryptoEncDe cryptoEncDe;
	private JTextArea sourceTextArea;
	private JTextArea destinationTextArea;
	boolean encrypt = true;

	CryptoActionListener(JTextField keyStoreFileField, JPasswordField keystorePasswordField, JTextField keyNameField, JPasswordField keyPasswordField, JTextArea sourceTextArea, JTextArea destinationTextArea, boolean encrypt) {

		this.keyStoreFileField = keyStoreFileField;
		
		this.keystorePasswordField = keystorePasswordField;
		this.keyNameField = keyNameField;
		this.keyPasswordField = keyPasswordField;
		
		this.cryptoEncDe = new CryptoEncDe();
		
		this.sourceTextArea = sourceTextArea;
		this.destinationTextArea = destinationTextArea;
		this.encrypt = encrypt;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub

		try {
			cryptoEncDe.init("jkes", new File(keyStoreFileField.getText()), keystorePasswordField.getPassword());
			
			String destinationText = "";
			if(encrypt)
				destinationText = new String(Base64.encode(cryptoEncDe.encrypt(keyNameField.getText(), keyPasswordField.getPassword(), sourceTextArea.getText())), "UTF-8");
			else
				destinationText = new String(cryptoEncDe.decrypt(keyNameField.getText(), keyPasswordField.getPassword(), Base64.decode(sourceTextArea.getText())), "UTF-8");
			
			destinationTextArea.setText(destinationText);
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		
	}

}