# -*- coding: utf-8 -*-

import smtplib
from email.mime.text import MIMEText

from app import config as config_module

config = config_module.get_config()


class MrPostman(object):
    """
    Please Mister Postman look and see
    """

    @classmethod
    def send_confirm_mail(cls, to, token_url):
        try:
            content_message = u"""

Plz, confirm you register in eve-planetary:

{}

            """.format(token_url)
            msg = MIMEText(content_message.encode('utf-8'), 'plain', 'utf-8')

            email_from = 'noreply@maethorin.com.br'

            msg['Subject'] = u'EVE Planetary – Register Confirmation'
            msg['From'] = email_from
            msg['To'] = to

            smtp = smtplib.SMTP(config.SMTP_SERVER, port=25)
            smtp.set_debuglevel(1)
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()

            login = config.EMAIL_LOGIN
            password = config.EMAIL_PASSWORD
            smtp.login(login, password)
            smtp.ehlo()

            smtp.sendmail(email_from, [to], msg.as_string())
            smtp.quit()
            return True
        except Exception:
            return False
