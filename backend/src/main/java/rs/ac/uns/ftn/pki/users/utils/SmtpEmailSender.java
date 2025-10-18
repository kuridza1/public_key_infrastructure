package rs.ac.uns.ftn.pki.users.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;

import jakarta.mail.internet.MimeMessage;
import java.util.Properties;

@Component
public class SmtpEmailSender {

    @Value("${email.smtp.host:localhost}")
    private String host;

    @Value("${email.smtp.port:25}")
    private int port;

    @Value("${email.smtp.user:}")
    private String user;

    @Value("${email.smtp.pass:}")
    private String pass;

    @Value("${email.from:no-reply@sudobox.local}")
    private String from;

    public void send(String toEmail, String subject, String htmlBody) {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setHost(host);
        sender.setPort(port);
        if (!user.isBlank()) {
            sender.setUsername(user);
            sender.setPassword(pass);
        }

        Properties props = sender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", String.valueOf(!user.isBlank()));
        props.put("mail.smtp.starttls.enable", "true"); // StartTLS when available
        props.put("mail.debug", "false");

        MimeMessage msg = sender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(msg, "UTF-8");
            helper.setFrom(from, "SudoBox");
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(htmlBody, true); // HTML
            sender.send(msg);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to send email", e);
        }
    }
}
