const bcrypt = require('bcryptjs');

async function hashAdminPassword() {
    const plaintextPassword = 'admin123'; // Bu sizin kullanmak istediğiniz admin şifresi (admin123)
    const saltRounds = 10; // Şifreleme gücü, 10 genellikle yeterlidir

    try {
        const hashedPassword = await bcrypt.hash(plaintextPassword, saltRounds);
        console.log('Admin şifresinin hashlenmiş hali (BUNU KOPYALA):', hashedPassword);
    } catch (error) {
        console.error('Şifre hashleme hatası:', error);
    } finally {
        process.exit(); // İşlem bitince programı kapat
    }
}

hashAdminPassword();