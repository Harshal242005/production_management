import { text } from "express";
import Mailgen from "mailgen";
import nodemailer from "nodemailer"


const sendEmail = async (options) =>  {
    const mailGenerator  = new Mailgen({
        theme:"default",
        product: {
            name: "Task Manager",
            link:"https://taskmanagelink.com"
        }
    })

    const emailTextual=   mailGenerator.generatePlaintext(options.mailgenContent)

    const emailHtml=   mailGenerator.generate(options.mailgenContent)

    const transporter =   nodemailer.createTransport({
      host: process.env.MAILTRAP_SMTP_HOST,
      port: process.env.MAILTRAP_SMTP_PORT,
      auth: {
        user: process.env.MAILTRAP_SMTP_USER,
        pass: process.env.MAILTRAP_SMTP_PASS
      },
    });

    const mail = {
      from: "mail.taskmanager@example.com",
      to: options.email,
      subject: options.subject,
      text: emailTextual, // Plain-text version of the message
      html: emailHtml, // HTML version of the message
    };

    try {
      const info = await transporter.sendMail(mail);
      console.log("✅ Email sent successfully to:", options.email);
      console.log("📧 Message ID:", info.messageId);
      return info;
    } catch (error) {
      console.error("❌ Email service failed!");
      console.error("Error:", error.message);
      throw error; // ← THIS IS THE KEY FIX: re-throw the error
    }
    
} 

const emailVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to App! We're very excited to have you on board.",
      action: {
        instructions:
          "To verify your email please click on the following button.",
        button: {
          color: "#0b9446",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};


const forgotPasswordVerificationMailgenContent = (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to App! We're very excited to have you on board.",
      action: {
        instructions:
          "To change your password please click on the following button.",
        button: {
          color: "#0b9446",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "We got a request to reset the password of your account.",
      action: {
        instructions:
          "To reset your password click on the following button or link.",
        button: {
          color: "#2c7e50ff",
          text: "reset password",
          link: passwordResetUrl,
        },
      },
      outro:
        "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
};


export {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
  forgotPasswordVerificationMailgenContent,
};