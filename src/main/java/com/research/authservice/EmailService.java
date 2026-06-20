package com.research.authservice;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Value("${spring.mail.username:noreply@obsidian.app}")
    private String fromEmail;

    @Value("${app.frontend-url:http://localhost:3001}")
    private String frontendUrl;

    public void sendOtp(String toEmail, String otp, String userName) {
        if (mailSender == null) {
            // Dev mode: no SMTP configured, log OTP to console
            log.info("[DEV] OTP email not sent (no mail server). OTP for {}: {}", toEmail, otp);
            return;
        }
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(fromEmail, "Obsidian Research");
            helper.setTo(toEmail);
            helper.setSubject("Your Obsidian sign-in code: " + otp);
            helper.setText(buildOtpHtml(otp, userName), true);
            mailSender.send(message);
            log.info("OTP email sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send OTP to {}: {}", toEmail, e.getMessage());
            throw new RuntimeException("Could not send verification email. Please try again.", e);
        }
    }

    private String buildOtpHtml(String otp, String userName) {
        String name = (userName != null && !userName.isBlank()) ? userName : "there";
        return """
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body style="font-family:Inter,system-ui,sans-serif;background:#F8F6F2;margin:0;padding:0;">
              <div style="max-width:500px;margin:40px auto;background:#fff;border-radius:20px;
                          box-shadow:0 8px 32px rgba(100,80,60,0.10);overflow:hidden;">
                <div style="background:linear-gradient(135deg,#C4956A,#9B8EC4);
                            padding:32px 40px;text-align:center;">
                  <div style="font-size:28px;color:#fff;font-weight:800;
                              font-family:Georgia,serif;">◆ Obsidian</div>
                  <div style="color:rgba(255,255,255,0.85);font-size:14px;
                              margin-top:6px;">AI Research Assistant</div>
                </div>
                <div style="padding:40px;">
                  <h2 style="color:#2B2B2B;margin:0 0 12px;font-size:22px;">Hi %s 👋</h2>
                  <p style="color:#6B6B6B;margin:0 0 28px;font-size:15px;line-height:1.6;">
                    Your one-time sign-in code for Obsidian is:
                  </p>
                  <div style="background:linear-gradient(135deg,rgba(196,149,106,0.08),
                              rgba(155,142,196,0.08));border:1px solid rgba(196,149,106,0.22);
                              border-radius:16px;padding:24px;text-align:center;margin-bottom:28px;">
                    <div style="font-size:48px;font-weight:800;letter-spacing:12px;
                                color:#2B2B2B;font-family:monospace;">%s</div>
                    <div style="color:#A0A0A0;font-size:13px;margin-top:8px;">
                      Expires in 5 minutes · 3 attempts allowed
                    </div>
                  </div>
                  <p style="color:#A0A0A0;font-size:13px;line-height:1.6;margin:0;">
                    If you didn't request this code, you can safely ignore this email.<br>
                    Never share this code with anyone.
                  </p>
                </div>
                <div style="background:#F8F6F2;padding:20px 40px;text-align:center;
                            border-top:1px solid rgba(196,149,106,0.15);">
                  <p style="color:#A0A0A0;font-size:12px;margin:0;">
                    © 2026 Obsidian Research Assistant
                  </p>
                </div>
              </div>
            </body>
            </html>
            """.formatted(name, otp);
    }
}
