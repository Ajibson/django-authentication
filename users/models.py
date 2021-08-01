from django.db import models
from django.utils import timezone

#import django Abstratc user for extension
from django.contrib.auth.models import AbstractUser

from django.dispatch import receiver
from django.db.models.signals import post_save


from django.utils.encoding import force_bytes 
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import BadHeaderError, send_mail
from django.template.loader import render_to_string

class User(AbstractUser):
    phone_number = models.CharField(max_length=30, blank=True)
    is_verified = models.BooleanField(default=False)


@receiver(post_save, sender = User)
def send_activation_email(sender, instance, created, **kwargs):
       if created:
            token = default_token_generator.make_token(instance)
            uid = urlsafe_base64_encode(force_bytes(instance.pk))
            email_template_name = "users/account_email.html"
            subject = "Account Varification"
            html_message = f"""
                        <div>

                    <h3>Hi { instance.first_name },</h3> 

                    <p>As a form of avoiding unrealistic and unserious users, we have to ensure email confirmation. 
                    Please click on the link to confirm your registration</p>

                    <a href=\"http://localhost:8000/activate/{uid}/{token}\" style="color:white; text-decoration: none;border-radius: 25px; background-color: #754C28; padding: 7px 25px;"> <strong>Verify Email<strong></a>

                    <br><br>If you think, it's not you, then just ignore this email. Thank you.  

                </div>"""
            c = {
                "email":instance.email,
                "domain":  'localhost:8000', 
                "site_name":"Account Verification",
                "uid": urlsafe_base64_encode(force_bytes(instance.pk)),
                "user":instance,
                'token': token,
                'protocol': 'https',
                }

            email_content = render_to_string(email_template_name, c)
            
            try:
                send_mail(subject, email_content, "helpraisemyfund@gmail.com", [instance.email], fail_silently=False, html_message=html_message)
            except BadHeaderError:
                pass


