from flask import url_for

from CTFd.utils import get_config
from CTFd.utils.config import get_mail_provider
from CTFd.utils.email import mailgun, smtp
from CTFd.utils.formatters import safe_format
from CTFd.utils.security.signing import serialize

DEFAULT_VERIFICATION_EMAIL_SUBJECT = "Подтвердите ваш аккаунт на {ctf_name}"
DEFAULT_VERIFICATION_EMAIL_BODY = (
    "Пожалуйста, перейдите по ссылке чтобы подтвердить ваш "
    "адрес электронной почты на {ctf_name}: {url}"
)
DEFAULT_SUCCESSFUL_REGISTRATION_EMAIL_SUBJECT = "Успешная регистрация на {ctf_name}"
DEFAULT_SUCCESSFUL_REGISTRATION_EMAIL_BODY = (
    "Вы успешно зарегистрировались на {ctf_name}!"
)
DEFAULT_USER_CREATION_EMAIL_SUBJECT = "Сообщение от {ctf_name}"
DEFAULT_USER_CREATION_EMAIL_BODY = (
    "Для вас был создан аккаунт на {ctf_name} в {url}. \n\n"
    "Имя пользователя: {name}\n"
    "Ваш пароль: {password}"
)
DEFAULT_PASSWORD_RESET_SUBJECT = "Смена пароля на {ctf_name}"
DEFAULT_PASSWORD_RESET_BODY = (
    "Вы просили сбросить ваш пароль? "
    "Если нет, проигнорируйте это сообщение. \n\n"
    "Перейдите по следующей ссылке чтобы сбросить ваш пароль:\n{url}"
)
DEFAULT_PASSWORD_CHANGE_ALERT_SUBJECT = "Подтверждение смены пароля {ctf_name}"
DEFAULT_PASSWORD_CHANGE_ALERT_BODY = (
    "Пароль для {ctf_name} был изменён.\n\n"
    "Если вы не меняли пароль сбросьте его здесь: {url}"
)


def sendmail(addr, text, subject="Сообщение от {ctf_name}"):
    subject = safe_format(subject, ctf_name=get_config("ctf_name"))
    provider = get_mail_provider()
    if provider == "smtp":
        return smtp.sendmail(addr, text, subject)
    if provider == "mailgun":
        return mailgun.sendmail(addr, text, subject)
    return False, "Настройки почты не заданы"


def password_change_alert(email):
    text = safe_format(
        get_config("password_change_alert_body") or DEFAULT_PASSWORD_CHANGE_ALERT_BODY,
        ctf_name=get_config("ctf_name"),
        ctf_description=get_config("ctf_description"),
        url=url_for("auth.reset_password", _external=True),
    )

    subject = safe_format(
        get_config("password_change_alert_subject")
        or DEFAULT_PASSWORD_CHANGE_ALERT_SUBJECT,
        ctf_name=get_config("ctf_name"),
    )
    return sendmail(addr=email, text=text, subject=subject)


def forgot_password(email):
    text = safe_format(
        get_config("password_reset_body") or DEFAULT_PASSWORD_RESET_BODY,
        ctf_name=get_config("ctf_name"),
        ctf_description=get_config("ctf_description"),
        url=url_for("auth.reset_password", data=serialize(email), _external=True),
    )

    subject = safe_format(
        get_config("password_reset_subject") or DEFAULT_PASSWORD_RESET_SUBJECT,
        ctf_name=get_config("ctf_name"),
    )
    return sendmail(addr=email, text=text, subject=subject)


def verify_email_address(addr):
    text = safe_format(
        get_config("verification_email_body") or DEFAULT_VERIFICATION_EMAIL_BODY,
        ctf_name=get_config("ctf_name"),
        ctf_description=get_config("ctf_description"),
        url=url_for(
            "auth.confirm", data=serialize(addr), _external=True, _method="GET"
        ),
    )

    subject = safe_format(
        get_config("verification_email_subject") or DEFAULT_VERIFICATION_EMAIL_SUBJECT,
        ctf_name=get_config("ctf_name"),
    )
    return sendmail(addr=addr, text=text, subject=subject)


def successful_registration_notification(addr):
    text = safe_format(
        get_config("successful_registration_email_body")
        or DEFAULT_SUCCESSFUL_REGISTRATION_EMAIL_BODY,
        ctf_name=get_config("ctf_name"),
        ctf_description=get_config("ctf_description"),
        url=url_for("views.static_html", _external=True),
    )

    subject = safe_format(
        get_config("successful_registration_email_subject")
        or DEFAULT_SUCCESSFUL_REGISTRATION_EMAIL_SUBJECT,
        ctf_name=get_config("ctf_name"),
    )
    return sendmail(addr=addr, text=text, subject=subject)


def user_created_notification(addr, name, password):
    text = safe_format(
        get_config("user_creation_email_body") or DEFAULT_USER_CREATION_EMAIL_BODY,
        ctf_name=get_config("ctf_name"),
        ctf_description=get_config("ctf_description"),
        url=url_for("views.static_html", _external=True),
        name=name,
        password=password,
    )

    subject = safe_format(
        get_config("user_creation_email_subject")
        or DEFAULT_USER_CREATION_EMAIL_SUBJECT,
        ctf_name=get_config("ctf_name"),
    )
    return sendmail(addr=addr, text=text, subject=subject)


def check_email_is_whitelisted(email_address):
    local_id, _, domain = email_address.partition("@")
    domain_whitelist = get_config("domain_whitelist")
    if domain_whitelist:
        domain_whitelist = [d.strip() for d in domain_whitelist.split(",")]
        if domain not in domain_whitelist:
            return False
    return True
