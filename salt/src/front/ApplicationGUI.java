package front;

import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;
import logic.Encryptor;
import logic.IEncryption;
import logic.PasswordBasedEncryption;

public class ApplicationGUI extends Application
{
    private static final String FILE_LOCATION = "encrypted.file";
    private static IEncryption encryption;

    private TextArea textArea;
    private Button encryptButton;
    private Button decryptButton;
    private GridPane gridPane;
    private TextField passwordField;

    public static void main(String[] args)
    {
        encryption = new Encryptor();
        Application.launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception
    {
        primaryStage.setScene(initializeViewObjects());
        primaryStage.show();
    }

    private Scene initializeViewObjects()
    {
        gridPane = ViewToolbox.buildStandardGridPane();

        passwordField = new TextField();

        textArea = new TextArea();

        encryptButton = new Button("Encrypt");
        encryptButton.setOnAction(this::encryptMessage);

        decryptButton = new Button("Decrypt");
        decryptButton.setOnAction(this::decryptMessage);

        gridPane.add(passwordField, 0, 0);
        gridPane.add(textArea, 0, 1);
        gridPane.add(encryptButton, 0, 2);
        gridPane.add(decryptButton, 0, 3);

        return ViewToolbox.buildSceneFromGridPane(gridPane);
    }

    private void encryptMessage(ActionEvent event)
    {
        encryption.encryption(textArea.getText(), passwordField.getText().toCharArray());
    }

    private void decryptMessage(ActionEvent event)
    {
        encryption.decryprion(FILE_LOCATION, passwordField.getText().toCharArray());
    }
}
