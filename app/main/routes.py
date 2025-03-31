from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_required
from app import db
from app.main import bp
from app.models import Message
from app.main.forms import MessageForm
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_encryption_key(password):
    salt = b'gizli-salt-degeri'  # Gerçek uygulamada güvenli bir salt kullanılmalı
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

@bp.route('/')
@bp.route('/index')
@login_required
def index():
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(content=form.message.data, author=current_user)
        # Mesajı şifrele
        key = get_encryption_key(current_user.password_hash)
        f = Fernet(key)
        message.encrypted_content = f.encrypt(form.message.data.encode()).decode()
        db.session.add(message)
        db.session.commit()
        flash('Mesajınız başarıyla gönderildi!')
        return redirect(url_for('main.index'))
    
    messages = Message.query.order_by(Message.timestamp.desc()).all()
    return render_template('index.html', title='Ana Sayfa', form=form, messages=messages)

@bp.route('/decrypt/<int:message_id>')
@login_required
def decrypt_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.author != current_user:
        flash('Bu mesajı çözmek için yetkiniz yok!')
        return redirect(url_for('main.index'))
    
    key = get_encryption_key(current_user.password_hash)
    f = Fernet(key)
    try:
        decrypted_content = f.decrypt(message.encrypted_content.encode()).decode()
        return render_template('decrypt.html', title='Mesaj Çöz', 
                             message=message, decrypted_content=decrypted_content)
    except:
        flash('Mesaj çözülemedi!')
        return redirect(url_for('main.index')) 