package front;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;
import logic.Encryptor;
import logic.IEncryption;

public class ApplicationGUI extends Application
{
    private static IEncryption encryption;

    private TextArea textArea;
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
        GridPane gridPane = ViewToolbox.buildStandardGridPane();

        passwordField = new TextField();

        textArea = new TextArea();

        Button encryptButton = new Button("Encrypt");
        encryptButton.setOnAction(event -> encryptMessage());

        Button decryptButton = new Button("Decrypt");
        decryptButton.setOnAction(event -> decryptMessage());

        gridPane.add(passwordField, 0, 0);
        gridPane.add(textArea, 0, 1);
        gridPane.add(encryptButton, 0, 2);
        gridPane.add(decryptButton, 0, 3);

        return ViewToolbox.buildSceneFromGridPane(gridPane);
    }

    private void encryptMessage()
    {
        encryption.encryption(textArea.getText(), passwordField.getText().toCharArray());
    }

    private void decryptMessage()
    {
        textArea.setText(encryption.decryprion(passwordField.getText().toCharArray()));
    }
}
