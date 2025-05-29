// Gerekli modüllerin dahil edilmesi
const dotenv = require('dotenv'); // dotenv modülünü burada require ediyoruz

// Ortam değişkenlerini yükle
// Eğer NODE_ENV 'test' ise test.env dosyasını yükle, aksi takdirde .env dosyasını yükle
dotenv.config();

const { nanoid } = require('nanoid');
const express = require('express'); // Express.js web framework'ü
const cors = require('cors'); // Cross-Origin Resource Sharing (CORS) için middleware
const path = require('path'); // Dosya yolları ile çalışmak için Node.js modülü
const { Pool } = require('pg'); // PostgreSQL veritabanı ile etkileşim için
const bcrypt = require('bcryptjs'); // Şifreleri hash'lemek için
const jwt = require('jsonwebtoken'); // JSON Web Token (JWT) oluşturmak ve doğrulamak için
const { createObjectCsvWriter } = require('csv-writer'); // CSV dosyası yazmak için kütüphane
const fs = require('fs'); // CSV dosyasını silmek için eklendi (geçici dosyalar için)
const pdf = require('html-pdf'); // HTML'den PDF oluşturmak için
const moment = require('moment'); // Tarih ve zaman işlemleri için

// Express uygulamasını başlat
const app = express();
const PORT = process.env.PORT || 3000; // Sunucunun çalışacağı port, .env'den veya varsayılan 3000
const JWT_SECRET = process.env.JWT_SECRET; // JWT gizli anahtarı, .env'den alınır

// JWT_SECRET'ın doğru yüklenip yüklenmediğini kontrol etmek için başlangıç logu
console.log('Sunucu Başlangıcı - JWT_SECRET Yüklendi:', JWT_SECRET ? 'Evet' : 'Hayır', 'Uzunluk:', JWT_SECRET ? JWT_SECRET.length : 0);

// Middleware: JSON body'leri ayrıştırma
app.use(express.json());
// Middleware: URL-encoded body'leri ayrıştırma
app.use(express.urlencoded({ extended: true }));
// Middleware: CORS ayarları
app.use(cors());

// PostgreSQL veritabanı bağlantı havuzu
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT || 5432,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false // Üretim ortamı için SSL ayarı
});

// Veritabanı havuz bağlantı olaylarını logla
pool.on('connect', () => {
    console.log('✅ PostgreSQL veritabanı havuzuna bir istemci bağlandı.');
});

pool.on('error', (err, client) => {
    console.error('!!! PostgreSQL havuzunda beklenmedik hata:', err);
});

// Middleware: İstek loglama (tüm gelen istekleri loglar)
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] İstek: ${req.method} ${req.url}`);
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
        const bodyCopy = { ...req.body };
        if (bodyCopy.password) {
            bodyCopy.password = '[ŞİFRE GİZLİ]'; // Şifreyi loglarda gizle
        }
        console.log('  Body:', JSON.stringify(bodyCopy));
    }
    next();
});

// Yardımcı fonksiyon: Audit Log kaydı
// Bu fonksiyon, veritabanındaki önemli değişiklikleri kaydeder.
async function logAudit(userId, username, actionType, tableName, recordId, oldValue, newValue) {
    try {
        await pool.query(
            'INSERT INTO audit_logs (user_id, user_username, action_type, table_name, record_id, old_value, new_value) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [userId, username, actionType, tableName, recordId, oldValue, newValue]
        );
    } catch (err) {
        console.error('Audit log kaydı sırasında hata:', err);
        // Audit log hatası, ana işlemin başarısız olmasına neden olmamalıdır.
    }
}

// AUTHENTICATION MIDDLEWARE
// JWT token'ını doğrulayan ve request objesine kullanıcı bilgilerini ekleyen middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Authorization: Bearer TOKEN

    if (token == null) {
        const error = new Error('Erişim için token gerekli.');
        error.status = 401; // Unauthorized
        return next(error);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("JWT Doğrulama Hatası:", err.message); // Hatanın nedenini logla
            const error = new Error('Geçersiz token veya süresi dolmuş.');
            error.status = 403; // Forbidden
            return next(error);
        }
        req.user = user; // Token'dan çözülen kullanıcı bilgilerini request objesine ekle
        next();
    });
};

// YETKİLENDİRME MIDDLEWARE'leri
// Sadece 'admin' rolüne sahip kullanıcıların erişimine izin verir.
const isAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        const error = new Error('Bu işlemi yapmaya yetkiniz yok.');
        error.status = 403; // Forbidden
        return next(error);
    }
    next();
};
 

// app.js dosyanızda middleware'lerin tanımlandığı bölüm:

// ... authenticateToken, isAdmin vb. middleware'leriniz ...

const checkPermission = (requiredPermissionKey) => {
    return async (req, res, next) => {
        try {
            // Kullanıcının authenticateToken middleware'i tarafından eklendiğini varsayıyoruz
            if (!req.user) {
                const error = new Error('Yetkilendirme için kullanıcı bilgisi bulunamadı.');
                error.status = 401; // Unauthorized
                return next(error);
            }

            const userId = req.user.id;
            const userRole = req.user.role;

            // 1. Admin Rolü Her Zaman İzinli
            if (userRole === 'admin') {
                return next(); // Admin ise tüm yetkilere sahip, devam et
            }

            // 2. Admin Değilse, Belirli Yetkiyi Kontrol Et
            const permissionCheckQuery = `
                SELECT 1 
                FROM user_permissions 
                WHERE user_id = $1 AND permission_key = $2;
            `;
            const result = await pool.query(permissionCheckQuery, [userId, requiredPermissionKey]);

            if (result.rows.length > 0) {
                return next(); // Yetki bulundu, devam et
            } else {
                // Yetki bulunamadı
                const error = new Error(`Bu işlemi yapmak için gerekli yetkiye (${requiredPermissionKey}) sahip değilsiniz.`);
                error.status = 403; // Forbidden
                return next(error);
            }
        } catch (error) {
            // Beklenmedik bir hata oluşursa
            next(error);
        }
    };
};


// YENİ MIDDLEWARE EKLE:
const isUserOrAdmin = (req, res, next) => {
    if (!req.user || (req.user.role !== 'user' && req.user.role !== 'admin')) {
        const error = new Error('Bu işlemi yapmaya yetkiniz yok. (User veya Admin rolü gerekli)');
        error.status = 403;
        return next(error);
    }
    next();
};

// Sadece 'uretim' veya 'admin' rolüne sahip kullanıcıların erişimine izin verir.
const isUretimOrAdmin = (req, res, next) => {
    if (!req.user || (req.user.role !== 'uretim' && req.user.role !== 'admin')) {
        const error = new Error('Bu işlemi yapmaya yetkiniz yok. (Üretim veya Admin rolü gerekli)');
        error.status = 403; // Forbidden
        return next(error);
    }
    next();
};

// Sadece 'sevkiyat' veya 'admin' rolüne sahip kullanıcıların erişimine izin verir.
const isSevkiyatOrAdmin = (req, res, next) => {
    if (!req.user || (req.user.role !== 'sevkiyat' && req.user.role !== 'admin')) {
        const error = new Error('Bu işlemi yapmaya yetkiniz yok. (Sevkiyat veya Admin rolü gerekli)');
        error.status = 403; // Forbidden
        return next(error);
    }
    next();
};


// Veritabanı tablolarını başlatan ve admin kullanıcıyı kontrol eden fonksiyon
// Uygulama başladığında veritabanı şemasının hazır olmasını sağlar
async function initializeDatabase() {
    console.log('--- initializeDatabase fonksiyonu BAŞLADI ---');

    let client;
    try {
        client = await pool.connect(); // Havuzdan bir istemci al
        console.log('✅ Veritabanına başarıyla bağlandı. Saat:', new Date().toISOString());

        // audit_logs tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.audit_logs
            (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                user_username VARCHAR(50),
                action_type VARCHAR(50) NOT NULL,
                table_name VARCHAR(50) NOT NULL,
                record_id INTEGER,
                old_value JSONB,
                new_value JSONB,
                timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "audit_logs" tablosu kontrol edildi/oluşturuldu.');

        // users tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.users
            (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(100) NOT NULL,
                full_name VARCHAR(100),
                role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'uretim', 'sevkiyat', 'user')),
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "users" tablosu kontrol edildi/oluşturuldu.');

        // company_type ENUM
        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'company_type') THEN
                    CREATE TYPE company_type AS ENUM ('customer', 'supplier', 'both');
                END IF;
            END
            $$;
        `);
        console.log('✅ "company_type" ENUM tipi kontrol edildi/oluşturuldu.');

        // product_type_enum ENUM
        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'product_type_enum') THEN
                    CREATE TYPE product_type_enum AS ENUM ('HAMMADDE', 'YARI_MAMUL', 'BITMIS_URUN');
                END IF;
            END
            $$;
        `);
        console.log('✅ "product_type_enum" ENUM tipi kontrol edildi/oluşturuldu.');

        
        // transaction_type_enum ENUM (GÜNCELLENMİŞ HALİ - sevkiyat_tam_iptal dahil)
        await client.query(`
            DO $$
            BEGIN
                -- Önce ENUM tipinin var olup olmadığını kontrol et
                IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'transaction_type_enum') THEN
                    -- Eğer ENUM tipi hiç yoksa, tüm değerlerle birlikte oluştur
                    CREATE TYPE transaction_type_enum AS ENUM (
                        'in', 
                        'out', 
                        'adjustment', 
                        'purchase_in', 
                        'production_in', 
                        'sevkiyat_iade',    -- Düzeltme için iade tipi
                        'sevkiyat_tam_iptal' -- Tamamen iptal için iade tipi (YENİ)
                    );
                ELSE
                    -- Eğer ENUM tipi zaten varsa, eksik olabilecek değerleri ekle
                    BEGIN ALTER TYPE transaction_type_enum ADD VALUE IF NOT EXISTS 'in'; EXCEPTION WHEN duplicate_object THEN NULL; END;
                    BEGIN ALTER TYPE transaction_type_enum ADD VALUE IF NOT EXISTS 'out'; EXCEPTION WHEN duplicate_object THEN NULL; END;
                    BEGIN ALTER TYPE transaction_type_enum ADD VALUE IF NOT EXISTS 'adjustment'; EXCEPTION WHEN duplicate_object THEN NULL; END;
                    BEGIN ALTER TYPE transaction_type_enum ADD VALUE IF NOT EXISTS 'purchase_in'; EXCEPTION WHEN duplicate_object THEN NULL; END;
                    BEGIN ALTER TYPE transaction_type_enum ADD VALUE IF NOT EXISTS 'production_in'; EXCEPTION WHEN duplicate_object THEN NULL; END;
                    BEGIN ALTER TYPE transaction_type_enum ADD VALUE IF NOT EXISTS 'sevkiyat_iade'; EXCEPTION WHEN duplicate_object THEN NULL; END;
                    BEGIN ALTER TYPE transaction_type_enum ADD VALUE IF NOT EXISTS 'sevkiyat_tam_iptal'; EXCEPTION WHEN duplicate_object THEN NULL; END; -- Yeni değer eklendi
                END IF;
            END
            $$;
        `);
        console.log('✅ "transaction_type_enum" ENUM tipi kontrol edildi/güncellendi (sevkiyat_iade ve sevkiyat_tam_iptal dahil).');

        // companies tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.companies
            (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                contact_person VARCHAR(255),
                phone VARCHAR(50),
                address TEXT,
                tax_office VARCHAR(100),
                tax_number VARCHAR(50),
                type company_type DEFAULT 'both',
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "companies" tablosu kontrol edildi/oluşturuldu.');

        // categories tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.categories
            (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL UNIQUE,
                description TEXT
            );
        `);
        console.log('✅ "categories" tablosu kontrol edildi/oluşturuldu.');

        // products tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.products
            (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                barcode VARCHAR(50) NOT NULL UNIQUE,
                stock INTEGER NOT NULL DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE,
                category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                min_stock_level INTEGER DEFAULT 0,
                product_type product_type_enum DEFAULT 'BITMIS_URUN' NOT NULL,
                unit_of_measure VARCHAR(50) DEFAULT 'adet' NOT NULL
            );
        `);
        console.log('✅ "products" tablosu kontrol edildi/oluşturuldu.');

        // YENİ: acquisition_methods alanını ekle
        await client.query(`
            ALTER TABLE products 
            ADD COLUMN IF NOT EXISTS acquisition_methods JSONB DEFAULT '["purchase", "production"]';
        `);
        console.log('✅ "products" tablosuna "acquisition_methods" alanı eklendi.');

        // bill_of_materials tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.bill_of_materials
            (
                id SERIAL PRIMARY KEY,
                finished_product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                raw_material_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                quantity_required NUMERIC(12, 4) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (finished_product_id, raw_material_id)
            );
        `);
        console.log('✅ "bill_of_materials" tablosu kontrol edildi/oluşturuldu.');

        // YENİ: product_context_rules tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.product_context_rules
            (
                id SERIAL PRIMARY KEY,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                context VARCHAR(50) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "product_context_rules" tablosu kontrol edildi/oluşturuldu.');

            // YENİ: SevkiyatSiparisleri Tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.sevkiyat_siparisleri
            (
                id SERIAL PRIMARY KEY,
                siparis_no VARCHAR(50) NOT NULL UNIQUE, -- Sistem tarafından generateTransactionCode ile üretilecek BENZERSİZ sipariş numarası
                kabin_kodu VARCHAR(100) NOT NULL,       -- Kullanıcı tarafından girilecek, TEKRARLANABİLİR kabin referans kodu
                firma_id INTEGER NOT NULL REFERENCES public.companies(id) ON DELETE RESTRICT,
                user_id INTEGER NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
                siparis_tarihi TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                referans_bina TEXT,
                durum VARCHAR(50) NOT NULL DEFAULT 'Hazırlanıyor',
                genel_notlar TEXT,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "sevkiyat_siparisleri" tablosu kontrol edildi/oluşturuldu.');

        // YENİ: SevkiyatSiparisiKalemleri Tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.sevkiyat_siparisi_kalemleri
            (
                id SERIAL PRIMARY KEY,
                sevkiyat_siparisi_id INTEGER NOT NULL REFERENCES public.sevkiyat_siparisleri(id) ON DELETE CASCADE,
                urun_id INTEGER NOT NULL REFERENCES public.products(id) ON DELETE RESTRICT,
                miktar NUMERIC(12, 4) NOT NULL,
                birim VARCHAR(50) NOT NULL,
                seri_numarasi TEXT,
                kalem_ozel_notlari TEXT,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "sevkiyat_siparisi_kalemleri" tablosu kontrol edildi/oluşturuldu.');


            // YENİ: units (Birimler) tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.units
            (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL UNIQUE,
                abbreviation VARCHAR(50) NOT NULL UNIQUE,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ "units" tablosu kontrol edildi/oluşturuldu.');

        // units tablosu için updated_at trigger'ını oluştur (PostgreSQL için)
        // Bu trigger, bir kayıt güncellendiğinde updated_at alanını otomatik olarak ayarlar.
        // Daha önce bu trigger fonksiyonunu genel olarak tanımladıysanız (update_updated_at_column),
        // sadece units tablosuna atama yapmanız yeterli olabilir.
        // Eğer "update_updated_at_column" fonksiyonu yoksa veya emin değilseniz, bu bloğu ekleyebilirsiniz.
        const triggerFunctionExists = await client.query(`
            SELECT 1 FROM pg_proc WHERE proname = 'update_updated_at_column';
        `);
        if (triggerFunctionExists.rows.length === 0) {
            await client.query(`
                CREATE OR REPLACE FUNCTION update_updated_at_column()
                RETURNS TRIGGER AS $$
                BEGIN
                   NEW.updated_at = NOW();
                   RETURN NEW;
                END;
                $$ language 'plpgsql';
            `);
            console.log('✅ "update_updated_at_column" trigger fonksiyonu oluşturuldu/kontrol edildi.');
        }

        const unitTriggerExists = await client.query(`
            SELECT 1 FROM pg_trigger WHERE tgname = 'update_units_updated_at' AND tgrelid = 'units'::regclass;
        `);
        if (unitTriggerExists.rows.length === 0) {
            await client.query(`
                CREATE TRIGGER update_units_updated_at
                BEFORE UPDATE ON public.units
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
            `);
            console.log('✅ "units" tablosu için updated_at trigger\'ı oluşturuldu.');
        }

        // ... (initializeDatabase fonksiyonunun geri kalanı) ...





        // transactions tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.transactions
            (
                id SERIAL PRIMARY KEY,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
                company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
                quantity INTEGER NOT NULL,
                type transaction_type_enum NOT NULL,
                transaction_date TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                product_stock_after_transaction INTEGER NOT NULL DEFAULT 0,
                transaction_code VARCHAR(50) UNIQUE
            );
        `);
        console.log('✅ "transactions" tablosu kontrol edildi/oluşturuldu.');




        // ... initializeDatabase fonksiyonunuzda, diğer CREATE TABLE komutlarından sonra ...

        // YENİ: permissions Tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.permissions
            (
                permission_key VARCHAR(100) PRIMARY KEY, -- Benzersiz yetki anahtarı (örn: "sevkiyat_olustur")
                description TEXT,                         -- Yetkinin açıklaması (örn: "Yeni Sevkiyat Siparişi Oluşturma Yetkisi")
                module VARCHAR(100)                       -- Yetkinin ait olduğu modül (örn: "Sevkiyat Yönetimi")
            );
        `);
        console.log('✅ "permissions" tablosu kontrol edildi/oluşturuldu.');

        // permissions Tablosunu Temel Yetkilerle Tohumlama (Seeding)
        const defaultPermissions = [
            // Sevkiyat Yönetimi Modülü
            { key: 'sevkiyat_siparisi_goruntule', description: 'Sevkiyat siparişlerini görüntüleyebilir', module: 'Sevkiyat Yönetimi' },
            { key: 'sevkiyat_siparisi_olustur', description: 'Yeni sevkiyat siparişi oluşturabilir', module: 'Sevkiyat Yönetimi' },
            { key: 'sevkiyat_siparisi_duzenle', description: 'Sevkiyat siparişlerini (taslak/düzeltiliyor iken) düzenleyebilir', module: 'Sevkiyat Yönetimi' },
            { key: 'sevkiyat_siparisi_sil', description: 'Sevkiyat siparişlerini (taslak iken) silebilir', module: 'Sevkiyat Yönetimi' },
            { key: 'sevkiyat_siparisi_sevket', description: 'Siparişi sevk edip stok düşümü yapabilir', module: 'Sevkiyat Yönetimi' },
            { key: 'sevkiyat_siparisi_duzeltme_baslat', description: 'Sevk edilmiş siparişte düzeltme başlatabilir (stok iadesi yapar)', module: 'Sevkiyat Yönetimi' },
            { key: 'sevkiyat_siparisi_duzeltme_tamamla', description: 'Başlatılmış düzeltmeyi tamamlayıp yeniden sevk edebilir', module: 'Sevkiyat Yönetimi' },
            { key: 'sevkiyat_siparisi_tamamen_iptal_et', description: 'Sevk edilmiş bir siparişi tamamen iptal edebilir (stok iadesi yapar)', module: 'Sevkiyat Yönetimi' },
            
            // Ürün Yönetimi Modülü (Örnek)
            { key: 'urun_goruntule', description: 'Ürünleri görüntüleyebilir', module: 'Ürün Yönetimi' },
            { key: 'urun_ekle', description: 'Yeni ürün ekleyebilir', module: 'Ürün Yönetimi' },
            { key: 'urun_duzenle', description: 'Ürün bilgilerini düzenleyebilir', module: 'Ürün Yönetimi' },
            { key: 'urun_sil', description: 'Ürün silebilir', module: 'Ürün Yönetimi' },

            // Kullanıcı Yönetimi Modülü (Örnek)
            { key: 'kullanici_goruntule', description: 'Kullanıcıları görüntüleyebilir', module: 'Kullanıcı Yönetimi' },
            { key: 'kullanici_ekle', description: 'Yeni kullanıcı ekleyebilir', module: 'Kullanıcı Yönetimi' },
            { key: 'kullanici_duzenle', description: 'Kullanıcı bilgilerini düzenleyebilir', module: 'Kullanıcı Yönetimi' },
            { key: 'kullanici_sil', description: 'Kullanıcı silebilir', module: 'Kullanıcı Yönetimi' },
            { key: 'kullanici_yetki_ata', description: 'Kullanıcılara yetki atayabilir/kaldırabilir', module: 'Kullanıcı Yönetimi' },

            // Raporlama Modülü (Örnek)
            { key: 'rapor_goruntule', description: 'Raporları görüntüleyebilir', module: 'Raporlama' }
            // ... İhtiyaç duyacağınız diğer tüm yetkileri buraya ekleyebilirsiniz ...
        ];

        for (const perm of defaultPermissions) {
            // Önce yetkinin var olup olmadığını kontrol et
            const checkPermQuery = 'SELECT permission_key FROM permissions WHERE permission_key = $1';
            const permResult = await client.query(checkPermQuery, [perm.key]);
            if (permResult.rows.length === 0) {
                // Eğer yetki yoksa ekle
                const insertPermQuery = 'INSERT INTO permissions (permission_key, description, module) VALUES ($1, $2, $3)';
                await client.query(insertPermQuery, [perm.key, perm.description, perm.module]);
                console.log(`✅ Varsayılan yetki eklendi: ${perm.key}`);
            }
        }
        console.log('✅ Varsayılan yetkiler kontrol edildi/eklendi.');





        // YENİ: user_permissions Tablosu
        await client.query(`
            CREATE TABLE IF NOT EXISTS public.user_permissions
            (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES public.users(id) ON DELETE CASCADE, -- Kullanıcı silinirse yetkileri de silinsin
                permission_key VARCHAR(100) NOT NULL REFERENCES public.permissions(permission_key) ON DELETE CASCADE, -- Yetki silinirse bu kayıt da silinsin
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                -- Bu tablo için updated_at genellikle gerekmeyebilir, ama isterseniz ekleyebilirsiniz.
                -- Eğer eklerseniz, trigger'ını da tanımlamayı unutmayın.
                UNIQUE (user_id, permission_key) -- Bir kullanıcıya aynı yetki birden fazla atanamaz
            );
        `);
        console.log('✅ "user_permissions" tablosu kontrol edildi/oluşturuldu.');




        // Admin kullanıcısı kontrolü
        const adminUsername = process.env.ADMIN_USERNAME || 'admin';
        const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
        const adminFullName = process.env.ADMIN_FULL_NAME || 'Sistem Yöneticisi';

        const adminExists = await client.query('SELECT * FROM users WHERE username = $1 AND role = $2', [adminUsername, 'admin']);

        if (adminExists.rows.length === 0) {
            console.log(`"${adminUsername}" adlı admin kullanıcısı bulunamadı, oluşturuluyor...`);
            const hashedPassword = await bcrypt.hash(adminPassword, 10);
            await client.query(
                'INSERT INTO users (username, password_hash, full_name, role) VALUES ($1, $2, $3, $4)',
                [adminUsername, hashedPassword, adminFullName, 'admin']
            );
            console.log(`✅ '${adminUsername}' adlı ilk admin kullanıcısı oluşturuldu.`);
        }

        // Varsayılan kategori kontrolü
        const uncategorizedExists = await client.query('SELECT id FROM categories WHERE name = $1', ['Kategorisiz']);
        if (uncategorizedExists.rows.length === 0) {
            await client.query('INSERT INTO categories (name, description) VALUES ($1, $2)', ['Kategorisiz', 'Bu kategoriye atanmamış ürünler.']);
            console.log('✅ "Kategorisiz" adlı varsayılan kategori oluşturuldu.');
        }

        console.log('✅ Veritabanı başarılı bir şekilde başlatıldı/güncellendi.');

        // ... (mevcut sevkiyat_siparisi_kalemleri oluşturma kodunuzun sonu) ...

        // YENİ: SevkiyatSiparisleri tablosu için updated_at trigger'ı
        const sevkiyatSiparisleriTriggerExists = await client.query(`
            SELECT 1 FROM pg_trigger WHERE tgname = 'update_sevkiyat_siparisleri_updated_at' AND tgrelid = 'sevkiyat_siparisleri'::regclass;
        `);
        if (sevkiyatSiparisleriTriggerExists.rows.length === 0) {
            await client.query(`
                CREATE TRIGGER update_sevkiyat_siparisleri_updated_at
                BEFORE UPDATE ON public.sevkiyat_siparisleri
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
            `);
            console.log('✅ "sevkiyat_siparisleri" tablosu için updated_at trigger\'ı oluşturuldu.');
        }

        // YENİ: SevkiyatSiparisiKalemleri tablosu için updated_at trigger'ı
        const sevkiyatKalemleriTriggerExists = await client.query(`
            SELECT 1 FROM pg_trigger WHERE tgname = 'update_sevkiyat_siparisi_kalemleri_updated_at' AND tgrelid = 'sevkiyat_siparisi_kalemleri'::regclass;
        `);
        if (sevkiyatKalemleriTriggerExists.rows.length === 0) {
            await client.query(`
                CREATE TRIGGER update_sevkiyat_siparisi_kalemleri_updated_at
                BEFORE UPDATE ON public.sevkiyat_siparisi_kalemleri
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
            `);
            console.log('✅ "sevkiyat_siparisi_kalemleri" tablosu için updated_at trigger\'ı oluşturuldu.');
        }

        // ... (initializeDatabase fonksiyonunun geri kalanı) ...


    } catch (err) {
        console.error('!!! Veritabanı başlatılırken hata oluştu:', err);
        process.exit(1);
    } finally {
        if (client) {
            client.release();
        }
    }
}

// app.js dosyanızın sonunda dışa aktarma (module.exports) satırı olmalı:
module.exports = { app, pool, initializeDatabase }; // initializeDatabase'i de dışa aktarıyoruz
// -------------------------------------------------------------
// API ROTLARI
// -------------------------------------------------------------

// Kullanıcı Girişi
app.post('/api/auth/login', async (req, res, next) => {
    const { username, password } = req.body;

    if (!username || !password) {
        const error = new Error('Kullanıcı adı ve şifre gereklidir.');
        error.status = 400;
        return next(error);
    }

    try {
        const userRes = await pool.query('SELECT * FROM users WHERE username = $1 AND is_active = TRUE', [username]);
        const user = userRes.rows[0];

        if (!user) {
            const error = new Error('Kullanıcı adı veya şifre yanlış.');
            error.status = 401; // Unauthorized
            return next(error);
        }

        // Şifreyi doğrula
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            const error = new Error('Kullanıcı adı veya şifre yanlış.');
            error.status = 401; // Unauthorized
            return next(error);
        }

        // Son giriş zamanını güncelle
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role, full_name: user.full_name },
            JWT_SECRET,
            { expiresIn: '1h' } // Token süresi
        );

        // Audit log: Giriş
        await logAudit(user.id, user.username, 'LOGIN', 'users', user.id, null, { username: user.username, role: user.role });

        res.json({ message: 'Giriş başarılı', token, user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role } });
    } catch (error) {
        next(error);
    }
});



// app.js dosyanızda, /api/users/:userId/permissions GET rotasından sonra veya uygun bir yere:




// Yeni Kullanıcı Kaydı (Sadece Admin)
app.post('/api/users', authenticateToken, isAdmin, async (req, res, next) => {
    const { username, password, full_name, role } = req.body;

    // Validasyon
    if (!username || username.length < 3) {
        const error = new Error('Kullanıcı adı en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (!password || password.length < 6) {
        const error = new Error('Şifre en az 6 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    const validRoles = ['admin', 'uretim', 'sevkiyat', 'user'];
    if (!role || !validRoles.includes(role)) {
        const error = new Error('Geçersiz kullanıcı rolü. Geçerli roller: admin, uretim, sevkiyat.');
        error.status = 400;
        return next(error);
    }
    if (!full_name || full_name.length < 3) {
        const error = new Error('Tam ad en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }

    try {
        const existingUser = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
        if (existingUser.rows.length > 0) {
            const error = new Error('Bu kullanıcı adı zaten mevcut.');
            error.status = 409; // Conflict
            return next(error);
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (username, password_hash, full_name, role) VALUES ($1, $2, $3, $4) RETURNING id, username, full_name, role, is_active, created_at, last_login',
            [username, hashedPassword, full_name, role]
        );

        await logAudit(req.user.id, req.user.username, 'CREATE', 'users', result.rows[0].id, null, result.rows[0]);
        res.status(201).json({ message: 'Kullanıcı başarıyla kaydedildi.', user: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

// Tüm kullanıcıları getir (Sadece Admin) - Sayfalama ve Sıralama Eklendi
app.get('/api/users', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        let { page = 1, limit = 10, sortBy = 'id', sortOrder = 'asc' } = req.query;

        page = parseInt(page);
        limit = parseInt(limit);
        const offset = (page - 1) * limit;

        if (isNaN(page) || page <= 0 || isNaN(limit) || limit <= 0) {
            const error = new Error('Geçersiz sayfa veya limit değeri.');
            error.status = 400;
            return next(error);
        }

        const validSortColumns = ['id', 'username', 'full_name', 'role', 'is_active', 'created_at', 'last_login'];
        const validSortOrders = ['asc', 'desc'];

        const column = validSortColumns.includes(sortBy) ? sortBy : 'id';
        const order = validSortOrders.includes(sortOrder) ? sortOrder : 'asc';

        const usersQuery = `SELECT id, username, full_name, role, is_active, created_at, last_login FROM users ORDER BY ${column} ${order} LIMIT $1 OFFSET $2`;
        const countQuery = 'SELECT COUNT(*) FROM users';

        const usersResult = await pool.query(usersQuery, [limit, offset]);
        const countResult = await pool.query(countQuery);

        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit);

        res.json({
            users: usersResult.rows,
            currentPage: page,
            totalPages: totalPages,
            totalItems: totalItems
        });
    } catch (err) {
        next(err);
    }
});

// Kullanıcıyı güncelle (Sadece Admin)
app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    const { username, password, full_name, role, is_active } = req.body;

    // Validasyon
    if (!username || username.length < 3) {
        const error = new Error('Kullanıcı adı en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    const validRoles = ['admin', 'uretim', 'sevkiyat', 'user']; // 'user' rolünü de ekledim, sizde vardı.
    if (!role || !validRoles.includes(role)) {
        // Hata mesajını biraz daha genel tutabiliriz veya tüm geçerli rolleri listeleyebiliriz.
        const error = new Error(`Geçersiz kullanıcı rolü. Geçerli roller: ${validRoles.join(', ')}.`);
        error.status = 400;
        return next(error);
    }
    if (!full_name || full_name.length < 3) {
        const error = new Error('Tam ad en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (typeof is_active !== 'boolean') {
        const error = new Error('Aktiflik durumu boolean olmalıdır (true veya false).');
        error.status = 400;
        return next(error);
    }

    try {
        // Eski kullanıcı bilgilerini al (audit log için)
        const oldUserResult = await pool.query('SELECT id, username, full_name, role, is_active, password_hash FROM users WHERE id = $1', [parseInt(id)]);
        if (oldUserResult.rows.length === 0) {
            const error = new Error('Kullanıcı bulunamadı.');
            error.status = 404;
            return next(error);
        }
        const oldUser = oldUserResult.rows[0];

        // Kullanıcı adı benzersizliğini kontrol et (kendisi hariç)
        const duplicateUsernameCheck = await pool.query('SELECT id FROM users WHERE username = $1 AND id != $2', [username, parseInt(id)]);
        if (duplicateUsernameCheck.rows.length > 0) {
            const error = new Error('Bu kullanıcı adı zaten başka bir kullanıcı tarafından kullanılıyor.');
            error.status = 409; // Conflict
            return next(error);
        }

        let updateQuery;
        let queryParams;

        if (password && password.trim() !== "") { // Eğer şifre de güncelleniyorsa ve boş değilse
            if (password.length < 6) {
                const error = new Error('Şifre en az 6 karakter olmalıdır.');
                error.status = 400;
                return next(error);
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            updateQuery = `
                UPDATE users 
                SET username = $1, 
                    full_name = $2, 
                    role = $3, 
                    is_active = $4, 
                    password_hash = $5 
                WHERE id = $6 
                RETURNING id, username, full_name, role, is_active, created_at, last_login;
            `;
            queryParams = [
                username,       // $1
                full_name,      // $2
                role,           // $3
                is_active,      // $4 (boolean)
                hashedPassword, // $5
                parseInt(id)    // $6
            ];
        } else { // Eğer sadece diğer bilgiler güncelleniyorsa (şifre hariç)
            updateQuery = `
                UPDATE users 
                SET username = $1, 
                    full_name = $2, 
                    role = $3, 
                    is_active = $4 
                WHERE id = $5 
                RETURNING id, username, full_name, role, is_active, created_at, last_login;
            `;
            queryParams = [
                username,       // $1
                full_name,      // $2
                role,           // $3
                is_active,      // $4 (boolean)
                parseInt(id)    // $5
            ];
        }

        const result = await pool.query(updateQuery, queryParams);
        
        // Güncelleme sonrası sonuç kontrolü (nadiren de olsa, ID bulunamazsa veya başka bir sorun olursa)
        if (result.rows.length === 0) {
            // Bu durum normalde oldUserResult kontrolünde yakalanmalı ama bir ek güvence.
            const error = new Error('Kullanıcı güncellenemedi veya bulunamadı.');
            error.status = 404; 
            return next(error);
        }

        await logAudit(req.user.id, req.user.username, 'UPDATE', 'users', parseInt(id), oldUser, result.rows[0]);
        res.json({ message: 'Kullanıcı başarıyla güncellendi.', user: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

// Kullanıcıyı sil (Sadece Admin)
app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    try {
        // Kullanıcının varlığını kontrol et (audit log için)
        const oldUserResult = await pool.query('SELECT id, username, full_name, role FROM users WHERE id = $1', [id]);
        if (oldUserResult.rows.length === 0) {
            const error = new Error('Kullanıcı bulunamadı.');
            error.status = 404;
            return next(error);
        }
        const oldUser = oldUserResult.rows[0];

        // Kendini silme engeli
        if (req.user.id == id) {
            const error = new Error('Kendi hesabınızı silemezsiniz.');
            error.status = 403;
            return next(error);
        }

        // Kullanıcıya bağlı stok hareketleri var mı kontrol et
        const transactionCountResult = await pool.query('SELECT COUNT(*) FROM transactions WHERE user_id = $1', [id]);
        const transactionCount = parseInt(transactionCountResult.rows[0].count);

        if (transactionCount > 0) {
            const error = new Error('Bu kullanıcıya bağlı stok hareketleri olduğu için silinemez.');
            error.status = 400;
            return next(error);
        }

        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id, username', [id]);
        if (result.rows.length === 0) {
            const error = new Error('Kullanıcı bulunamadı.');
            error.status = 404;
            return next(error);
        }

        await logAudit(req.user.id, req.user.username, 'DELETE', 'users', id, oldUser, null);
        res.json({ message: 'Kullanıcı başarıyla silindi.', user: result.rows[0] });
    } catch (err) {
        next(err);
    }
});


// app.js dosyanızda, /api/permissions GET rotasından sonra veya uygun bir yere:

// Bir Kullanıcının Mevcut Yetkilerini Listeleme
// Bu endpoint'e erişimi admin veya 'kullanici_yetki_ata' gibi bir yetkiye sahip kullanıcılarla kısıtlayabilirsiniz.
app.get('/api/users/:userId/permissions', authenticateToken, checkPermission('kullanici_yetki_ata'), async (req, res, next) => {
    const { userId } = req.params;

    if (isNaN(parseInt(userId))) {
        const error = new Error('Geçersiz kullanıcı ID formatı.');
        error.status = 400;
        return next(error);
    }

    try {
        // Önce kullanıcının var olup olmadığını kontrol edebiliriz (opsiyonel)
        const userCheckQuery = 'SELECT id FROM users WHERE id = $1';
        const userCheckResult = await pool.query(userCheckQuery, [parseInt(userId)]);
        if (userCheckResult.rows.length === 0) {
            const error = new Error('Kullanıcı bulunamadı.');
            error.status = 404;
            return next(error);
        }

        const query = `
            SELECT 
                up.permission_key,
                p.description,
                p.module
            FROM user_permissions up
            JOIN permissions p ON up.permission_key = p.permission_key
            WHERE up.user_id = $1
            ORDER BY p.module ASC, up.permission_key ASC;
        `;
        const result = await pool.query(query, [parseInt(userId)]);

        res.json({ userPermissions: result.rows });

    } catch (error) {
        console.error(`Kullanıcı (ID: ${userId}) yetkileri listelenirken hata oluştu:`, error);
        next(error);
    }
});





// app.js dosyanızda, /api/users/:userId/permissions GET rotasından sonra veya uygun bir yere:

// Bir Kullanıcının Yetkilerini Güncelleme
// Bu endpoint'e erişimi admin veya 'kullanici_yetki_ata' gibi bir yetkiye sahip kullanıcılarla kısıtlayın.
app.put('/api/users/:userId/permissions', authenticateToken, checkPermission('kullanici_yetki_ata'), async (req, res, next) => {
    const { userId } = req.params; // Yetkileri güncellenecek kullanıcının ID'si
    const { permissions: newPermissionKeys } = req.body; // ['permission_key1', 'permission_key2', ...] formatında bir dizi bekleniyor
    
    const requestingUserId = req.user.id; // İşlemi yapan admin/yetkili kullanıcı
    const requestingUsername = req.user.username;

    if (isNaN(parseInt(userId))) {
        const error = new Error('Geçersiz kullanıcı ID formatı.');
        error.status = 400;
        return next(error);
    }

    if (!Array.isArray(newPermissionKeys)) {
        const error = new Error('İstek gövdesinde "permissions" adında bir yetki anahtarları dizisi gönderilmelidir.');
        error.status = 400;
        return next(error);
    }

    // Admin kullanıcısının yetkileri değiştirilemesin (ID'si 1 olanın admin olduğunu varsayıyoruz, bu kontrolü kendi admin tanımınıza göre güncelleyin)
    // Veya req.user.role === 'admin' ve req.user.id === parseInt(userId) gibi bir kontrol de olabilir.
    // Şimdilik, admin rolüne sahip bir kullanıcının kendi yetkilerini veya başka bir adminin yetkilerini değiştiremeyeceğini varsayalım.
    // Ancak, bir adminin başka bir NON-ADMIN kullanıcının yetkilerini değiştirebilmesi gerekir.
    // Bu mantık sizin iş kurallarınıza göre detaylandırılmalı.
    // Örnek olarak: Eğer yetkisi değiştirilmek istenen kullanıcı admin ise ve değiştiren de aynı admin değilse (ki bu anlamsız) hata ver.
    // Daha basit bir kural: Admin rolündeki kullanıcıların yetkileri bu endpoint üzerinden değiştirilemez.
    const targetUserRes = await pool.query('SELECT role FROM users WHERE id = $1', [parseInt(userId)]);
    if (targetUserRes.rows.length === 0) {
        const error = new Error('Yetkileri güncellenecek kullanıcı bulunamadı.');
        error.status = 404;
        return next(error);
    }
    if (targetUserRes.rows[0].role === 'admin') {
        const error = new Error('Admin rolündeki kullanıcıların yetkileri bu arayüzden değiştirilemez.');
        error.status = 403; // Forbidden
        return next(error);
    }


    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Transaction başlat

        // 1. Kullanıcının mevcut tüm yetkilerini sil (user_permissions tablosundan)
        const deleteOldPermissionsQuery = 'DELETE FROM user_permissions WHERE user_id = $1';
        await client.query(deleteOldPermissionsQuery, [parseInt(userId)]);

        // 2. Yeni yetki listesindeki her bir permission_key için yeni kayıtlar ekle
        // Opsiyonel: Gönderilen permission_key'lerin permissions tablosunda var olup olmadığını kontrol edebilirsiniz.
        // Bu örnekte, var olduklarını varsayıyoruz.
        if (newPermissionKeys.length > 0) {
            const insertPromises = newPermissionKeys.map(permissionKey => {
                if (typeof permissionKey !== 'string' || permissionKey.trim() === '') {
                    // Geçersiz bir permissionKey formatı gelirse diye bir kontrol
                    console.warn(`Geçersiz permissionKey formatı atlandı: ${permissionKey}`);
                    return Promise.resolve(); // Bu key'i atla, diğerleriyle devam et
                }
                const insertNewPermissionQuery = `
                    INSERT INTO user_permissions (user_id, permission_key) 
                    VALUES ($1, $2)
                    ON CONFLICT (user_id, permission_key) DO NOTHING; 
                    -- ON CONFLICT eklemek, nadir de olsa bir çakışma olursa hatayı önler
                `;
                return client.query(insertNewPermissionQuery, [parseInt(userId), permissionKey.trim()]);
            });
            await Promise.all(insertPromises);
        }
        
        // Audit Log (Bu işlem biraz daha karmaşık bir log gerektirebilir: eski yetkiler vs yeni yetkiler)
        // Şimdilik genel bir log tutalım.
        await logAudit(requestingUserId, requestingUsername, 'UPDATE_USER_PERMISSIONS', 'user_permissions', parseInt(userId), 
            { note: `Kullanıcı ${userId} için yetkiler güncellendi.` }, 
            { newPermissions: newPermissionKeys }
        );

        await client.query('COMMIT'); // Her şey yolundaysa transaction'ı onayla

        // Güncellenmiş yetkileri kullanıcıya geri döndürebiliriz (opsiyonel)
        const updatedPermissionsQuery = `
            SELECT up.permission_key, p.description, p.module
            FROM user_permissions up
            JOIN permissions p ON up.permission_key = p.permission_key
            WHERE up.user_id = $1
            ORDER BY p.module ASC, up.permission_key ASC;
        `;
        const updatedResult = await client.query(updatedPermissionsQuery, [parseInt(userId)]);

        res.json({ 
            message: `Kullanıcı (ID: ${userId}) için yetkiler başarıyla güncellendi.`,
            updatedUserPermissions: updatedResult.rows 
        });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
         // Eğer foreign key ihlali olursa (permission_key, permissions tablosunda yoksa)
        if (error.code === '23503') {
            error.message = 'Gönderilen yetki anahtarlarından bazıları sistemde tanımlı değil veya kullanıcı ID geçersiz.';
            error.status = 400;
        }
        next(error);
    } finally {
        if (client) {
            client.release();
        }
    }
});


// app.js dosyanızda uygun bir yere:

// Tüm Tanımlı Yetkileri Listeleme
// Bu endpoint'e erişimi admin veya özel bir yetkiye (örn: 'kullanici_yetki_goruntule') sahip kullanıcılarla kısıtlayabilirsiniz.
// Şimdilik sadece authenticateToken ekliyorum, gerekirse rol/yetki kontrolü eklersiniz.
app.get('/api/permissions', authenticateToken, checkPermission('kullanici_yetki_ata'), async (req, res, next) => {
    try {
        const query = `
            SELECT 
                permission_key, 
                description, 
                module 
            FROM permissions
            ORDER BY module ASC, permission_key ASC; 
            -- Modüle ve sonra yetki anahtarına göre sırala
        `;
        const result = await pool.query(query);

        res.json({ permissions: result.rows });

    } catch (error) {
        console.error('Yetkiler listelenirken hata oluştu:', error);
        next(error);
    }
});



// ------------------- ÜRÜN YÖNETİMİ API'leri -------------------

// Ürün Ekle (Sadece Üretim veya Admin)
app.post('/api/products', authenticateToken, isUretimOrAdmin, async (req, res, next) => {
    const { name, barcode, stock, is_active, category_id, min_stock_level, product_type, unit_of_measure } = req.body;

    // Validasyon
    if (!name || name.length < 3) {
        const error = new Error('Ürün adı en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (!barcode || barcode.length < 3) {
        const error = new Error('Barkod en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (typeof stock !== 'number' || stock < 0) {
        const error = new Error('Stok miktarı sıfırdan küçük olamaz ve sayı olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (typeof is_active !== 'boolean') {
        const error = new Error('Aktiflik durumu boolean olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (category_id && (typeof category_id !== 'number' || category_id <= 0)) {
        const error = new Error('Geçersiz kategori ID formatı.');
        error.status = 400;
        return next(error);
    }
    if (typeof min_stock_level !== 'number' || min_stock_level < 0) {
        const error = new Error('Minimum stok seviyesi sıfırdan küçük olamaz ve sayı olmalıdır.');
        error.status = 400;
        return next(error);
    }
    // YENİ VALIDASYONLAR
    const validProductTypes = ['HAMMADDE', 'YARI_MAMUL', 'BITMIS_URUN'];
    if (!product_type || !validProductTypes.includes(product_type)) {
        const error = new Error(`Geçersiz ürün tipi. Geçerli tipler: ${validProductTypes.join(', ')}.`);
        error.status = 400;
        return next(error);
    }
    if (!unit_of_measure || unit_of_measure.length < 1 || unit_of_measure.length > 50) {
        const error = new Error('Ölçü birimi 1 ile 50 karakter arasında olmalıdır.');
        error.status = 400;
        return next(error);
    }
    // YENİ VALIDASYONLAR SONU
    try {
        const existingProduct = await pool.query('SELECT id FROM products WHERE barcode = $1', [barcode]);
        if (existingProduct.rows.length > 0) {
            const error = new Error('Bu barkoda sahip bir ürün zaten mevcut.');
            error.status = 409; // Conflict
            return next(error);
        }

        const result = await pool.query(
            // YENİ ALANLAR SORGULA EKLENDİ
            'INSERT INTO products (name, barcode, stock, is_active, category_id, min_stock_level, product_type, unit_of_measure) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
            [name, barcode, stock, is_active, category_id || null, min_stock_level || 0, product_type, unit_of_measure] // YENİ ALANLAR EKLENDİ
        );
        await logAudit(req.user.id, req.user.username, 'CREATE', 'products', result.rows[0].id, null, result.rows[0]);
        res.status(201).json({ message: 'Ürün başarıyla eklendi.', product: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

// Ürünleri Getir (Filtreleme, Arama, Sayfalama, Sıralama, Kategoriye göre filtreleme)
app.get('/api/products', authenticateToken, async (req, res, next) => {
    try {
        // YENİ productType FİLTRESİ EKLENDİ
        let { page = 1, limit = 10, search = '', status = 'all', critical = 'false', categoryId = '', productType = '', sortBy = 'id', sortOrder = 'asc' } = req.query;


        page = parseInt(page);
        limit = parseInt(limit);
        const offset = (page - 1) * limit;

        if (isNaN(page) || page <= 0 || isNaN(limit) || limit <= 0) {
            const error = new Error('Geçersiz sayfa veya limit değeri.');
            error.status = 400;
            return next(error);
        }

        // Sıralama kolonları ve yönleri için güvenli liste
        // YENİ ALANLAR SIRALAMA LİSTESİNE EKLENDİ
        const validSortColumns = ['id', 'name', 'barcode', 'stock', 'is_active', 'min_stock_level', 'category_name', 'product_type', 'unit_of_measure'];
        const validSortOrders = ['asc', 'desc'];

        const column = validSortColumns.includes(sortBy) ? sortBy : 'id';
        const order = validSortOrders.includes(sortOrder) ? sortOrder : 'asc';

        let whereClauses = [];
        let queryParams = [];
        let paramIndex = 1;

        // Arama terimi
        if (search) {
            whereClauses.push(`(LOWER(p.name) LIKE $${paramIndex} OR LOWER(p.barcode) LIKE $${paramIndex})`);
            queryParams.push(`%${search.toLowerCase()}%`);
            paramIndex++;
        }

        // Stok Durumu Filtresi
        if (status && status !== 'all') {
            if (status === 'active') {
                whereClauses.push(`p.is_active = TRUE`); // Sadece aktif ürünler
            } else if (status === 'inactive') {
                whereClauses.push(`p.is_active = FALSE`); // Sadece pasif ürünler
            }
        }

        // Kritik Stok Filtresi
        if (critical === 'true') {
            whereClauses.push(`p.stock <= p.min_stock_level AND p.is_active = TRUE AND p.min_stock_level > 0`);
        }

        // Kategori Filtresi
        if (categoryId) {
            const parsedCategoryId = parseInt(categoryId);
            if (!isNaN(parsedCategoryId)) {
                whereClauses.push(`p.category_id = $${paramIndex}`);
                queryParams.push(parsedCategoryId);
                paramIndex++;
            } else {
                const error = new Error('Geçersiz kategori ID formatı.');
                error.status = 400;
                return next(error);
            }
        }
        
        // YENİ: Ürün Tipi Filtresi
        if (productType) {
    const types = productType.split(',').map(t => t.trim().toUpperCase());
    const validProductTypes = ['HAMMADDE', 'YARI_MAMUL', 'BITMIS_URUN'];
    const validTypes = types.filter(t => validProductTypes.includes(t));
    
    if (validTypes.length > 0) {
        const placeholders = validTypes.map((_, i) => `$${paramIndex + i}`).join(',');
        whereClauses.push(`p.product_type IN (${placeholders})`);
        queryParams.push(...validTypes);
        paramIndex += validTypes.length;
    }
}
        // YENİ FİLTRE SONU


        const whereCondition = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        // Ürünleri ve kategori adını birlikte çekiyoruz
        
         // YENİ ALANLAR SELECT'E EKLENDİ
        let productsQuery = `
            SELECT
                p.id, p.name, p.barcode, p.stock, p.is_active, p.min_stock_level,
                p.product_type, p.unit_of_measure, -- YENİ ALANLAR
                c.name AS category_name, c.id AS category_id
            FROM
                products p
            LEFT JOIN
                categories c ON p.category_id = c.id
            ${whereCondition}
        `;
        // ... (countQuery ve sıralama mantığı aynı kalabilir, finalSortColumn için p.product_type, p.unit_of_measure eklenebilir) ...
        let countQuery = `
            SELECT COUNT(*)
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ${whereCondition}
        `;

        
        // Sıralama işlemi için 'category_name' doğrudan kullanılamaz, JOIN olduğu için
        // finalSortColumn ataması genişletilebilir:
        let finalSortColumn = `p.${column}`;
        if (column === 'category_name') {
            finalSortColumn = 'c.name';
        } else if (column === 'product_type') {
            finalSortColumn = 'p.product_type';
        } else if (column === 'unit_of_measure') {
            finalSortColumn = 'p.unit_of_measure';
        }
        
        
        
        productsQuery += ` ORDER BY ${finalSortColumn} ${order} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        queryParams.push(limit, offset);

        const productsResult = await pool.query(productsQuery, queryParams);
        const countResult = await pool.query(countQuery, queryParams.slice(0, queryParams.length - 2)); // Limit ve offset olmadan sayım

        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit);

        res.json({
            products: productsResult.rows,
            currentPage: page,
            totalPages: totalPages,
            totalItems: totalItems
        });
    } catch (err) {
        next(err);
    }
});

// YENİ: Smart Context Endpoint

app.get('/api/products/context/:context', authenticateToken, async (req, res, next) => {
    const { context } = req.params; // 'purchase' veya 'production'
    
    try {
        let { page = 1, limit = 10, search = '', sortBy = 'id', sortOrder = 'asc' } = req.query;
        
        page = parseInt(page);
        limit = parseInt(limit);
        const offset = (page - 1) * limit;

        let whereClauses = ['p.is_active = TRUE'];
        let queryParams = [];
        let paramIndex = 1;

        // Context filtreleme
        if (context === 'purchase') {
            whereClauses.push(`p.acquisition_methods @> '["purchase"]'`);
        } else if (context === 'production') {
            whereClauses.push(`p.acquisition_methods @> '["production"]'`);
            // BOM kontrolü ekle
            whereClauses.push(`EXISTS(SELECT 1 FROM bill_of_materials WHERE finished_product_id = p.id)`);
        }

        // Arama terimi
        if (search) {
            whereClauses.push(`(LOWER(p.name) LIKE $${paramIndex} OR LOWER(p.barcode) LIKE $${paramIndex})`);
            queryParams.push(`%${search.toLowerCase()}%`);
            paramIndex++;
        }

        const whereCondition = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        let productsQuery = `
            SELECT
                p.id, p.name, p.barcode, p.stock, p.is_active, p.min_stock_level,
                p.product_type, p.unit_of_measure, p.acquisition_methods,
                c.name AS category_name, c.id AS category_id
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ${whereCondition}
            ORDER BY p.${sortBy} ${sortOrder}
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        queryParams.push(limit, offset);

        let countQuery = `
            SELECT COUNT(*)
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            ${whereCondition}
        `;

        const productsResult = await pool.query(productsQuery, queryParams);
        const countResult = await pool.query(countQuery, queryParams.slice(0, queryParams.length - 2));

        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit);

        res.json({
            products: productsResult.rows,
            context: context,
            currentPage: page,
            totalPages: totalPages,
            totalItems: totalItems
        });
    } catch (err) {
        next(err);
    }
});
// Ürün Güncelle (Sadece Üretim veya Admin)
app.put('/api/products/:id', authenticateToken, isUretimOrAdmin, async (req, res, next) => {
    const { id } = req.params;
    const { name, barcode, stock, is_active, category_id, min_stock_level, product_type, unit_of_measure } = req.body; // YENİ ALANLAR EKLENDİ

    // Validasyon
    if (!name || name.length < 3) {
        const error = new Error('Ürün adı en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (!barcode || barcode.length < 3) {
        const error = new Error('Barkod en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (typeof stock !== 'number' || stock < 0) {
        const error = new Error('Stok miktarı sıfırdan küçük olamaz ve sayı olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (typeof is_active !== 'boolean') {
        const error = new Error('Aktiflik durumu boolean olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (category_id && (typeof category_id !== 'number' || category_id <= 0)) {
        const error = new Error('Geçersiz kategori ID formatı.');
        error.status = 400;
        return next(error);
    }
    if (typeof min_stock_level !== 'number' || min_stock_level < 0) {
        const error = new Error('Minimum stok seviyesi sıfırdan küçük olamaz ve sayı olmalıdır.');
        error.status = 400;
        return next(error);
    }
    
    // YENİ VALIDASYONLAR
    const validProductTypes = ['HAMMADDE', 'YARI_MAMUL', 'BITMIS_URUN'];
    if (!product_type || !validProductTypes.includes(product_type)) {
        const error = new Error(`Geçersiz ürün tipi. Geçerli tipler: ${validProductTypes.join(', ')}.`);
        error.status = 400;
        return next(error);
    }
    if (!unit_of_measure || unit_of_measure.length < 1 || unit_of_measure.length > 50) {
        const error = new Error('Ölçü birimi 1 ile 50 karakter arasında olmalıdır.');
        error.status = 400;
        return next(error);
    }
    // YENİ VALIDASYONLAR SONU
    

     try {
        const oldProductResult = await pool.query('SELECT * FROM products WHERE id = $1', [id]); // TÜM ALANLARI ALMAK DAHA İYİ OLABİLİR AUDIT İÇİN
        if (oldProductResult.rows.length === 0) {
            const error = new Error('Ürün bulunamadı.');
            error.status = 404;
            return next(error);
        }
        const oldProduct = oldProductResult.rows[0];

        // Barkodun başka bir ürüne ait olup olmadığını kontrol et (güncelleme yaparken kendi barkodunu göz ardı et)
        const existingBarcode = await pool.query('SELECT id FROM products WHERE barcode = $1 AND id != $2', [barcode, id]);
        if (existingBarcode.rows.length > 0) {
            const error = new Error('Bu barkoda sahip başka bir ürün zaten mevcut.');
            error.status = 409; // Conflict
            return next(error);
        }

        const result = await pool.query(
            // YENİ ALANLAR SORGULA EKLENDİ
            'UPDATE products SET name = $1, barcode = $2, stock = $3, is_active = $4, category_id = $5, min_stock_level = $6, product_type = $7, unit_of_measure = $8 WHERE id = $9 RETURNING *',
            [name, barcode, stock, is_active, category_id || null, min_stock_level || 0, product_type, unit_of_measure, id] // YENİ ALANLAR EKLENDİ
        );
        await logAudit(req.user.id, req.user.username, 'UPDATE', 'products', id, oldProduct, result.rows[0]);
        res.json({ message: 'Ürün başarıyla güncellendi.', product: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

// Ürün Kategorisini Güncelle (Yeni Endpoint)
app.put('/api/products/:id/category', authenticateToken, isUretimOrAdmin, async (req, res, next) => {
    const { id } = req.params; // Ürün ID'si
    const { category_id } = req.body; // Yeni kategori ID'si (null olabilir)

    // Validasyon
    if (category_id !== null && (typeof category_id !== 'number' || category_id <= 0)) {
        const error = new Error('Geçersiz kategori ID formatı. Sayı olmalı veya null olmalıdır.');
        error.status = 400;
        return next(error);
    }

    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // Eski ürün bilgilerini al (audit log için)
            const oldProductResult = await client.query('SELECT id, name, category_id FROM products WHERE id = $1 FOR UPDATE', [id]);
            if (oldProductResult.rows.length === 0) {
                const error = new Error('Ürün bulunamadı.');
                error.status = 404;
                return next(error);
            }
            const oldProduct = oldProductResult.rows[0];

            // Eğer yeni bir kategori ID'si varsa, bu kategorinin varlığını kontrol et
            if (category_id !== null) {
                const categoryExists = await client.query('SELECT id FROM categories WHERE id = $1', [category_id]);
                if (categoryExists.rows.length === 0) {
                    const error = new Error('Belirtilen kategori bulunamadı.');
                    error.status = 404;
                    return next(error);
                }
            }

            const result = await client.query(
                'UPDATE products SET category_id = $1 WHERE id = $2 RETURNING id, name, category_id',
                [category_id, id]
            );
            await logAudit(req.user.id, req.user.username, 'UPDATE_CATEGORY', 'products', id, oldProduct, result.rows[0]);

            await client.query('COMMIT');
            res.json({ message: 'Ürün kategorisi başarıyla güncellendi.', product: result.rows[0] });

        } catch (err) {
            await client.query('ROLLBACK');
            next(err);
        } finally {
            client.release();
        }
    } catch (err) {
        next(err);
    }
});


// Ürün Sil (Sadece Admin) - İlişkili hareket varsa pasif yapar, yoksa siler
app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const oldProductResult = await client.query('SELECT * FROM products WHERE id = $1 FOR UPDATE', [id]);
            if (oldProductResult.rows.length === 0) {
                const error = new Error('Ürün bulunamadı.');
                error.status = 404;
                return next(error);
            }
            const oldProduct = oldProductResult.rows[0];

            // Ürüne bağlı stok hareketleri var mı kontrol et
            const transactionCountResult = await client.query('SELECT COUNT(*) FROM transactions WHERE product_id = $1', [id]);
            const transactionCount = parseInt(transactionCountResult.rows[0].count);

            if (transactionCount > 0) {
                // Hareket varsa, ürünü pasif hale getir
                const updateResult = await client.query('UPDATE products SET is_active = FALSE WHERE id = $1 RETURNING *', [id]);
                await logAudit(req.user.id, req.user.username, 'DEACTIVATE', 'products', id, oldProduct, updateResult.rows[0]);
                await client.query('COMMIT');
                res.status(200).json({ message: 'Ürüne bağlı hareketler olduğu için ürün pasif hale getirildi.', product: updateResult.rows[0] });
            } else {
                // Hareket yoksa, ürünü tamamen sil
                await client.query('DELETE FROM products WHERE id = $1', [id]);
                await logAudit(req.user.id, req.user.username, 'DELETE', 'products', id, oldProduct, null);
                await client.query('COMMIT');
                res.status(200).json({ message: 'Ürün başarıyla silindi.' });
            }
        } catch (err) {
            await client.query('ROLLBACK');
            next(err);
        } finally {
            client.release();
        }
    } catch (err) {
        next(err);
    }
});


// ------------------- ÜRÜN REÇETESİ (BOM) API'leri -------------------

// Reçeteye Malzeme Ekle (YETKİLENDİRME GEÇİCİ OLARAK KALDIRILDI - SONRA EKLENECEK!)
app.post('/api/bill-of-materials', authenticateToken, async (req, res, next) => { // isUretimOrAdmin KALDIRILDI
    const { finished_product_id, raw_material_id, quantity_required } = req.body;
    const userId = req.user.id; // authenticateToken'dan geliyor
    const username = req.user.username; // authenticateToken'dan geliyor

    // Validasyon
    if (!finished_product_id || typeof finished_product_id !== 'number' || finished_product_id <= 0) {
        const error = new Error('Geçerli bir bitmiş ürün ID\'si gereklidir.');
        error.status = 400;
        return next(error);
    }
    if (!raw_material_id || typeof raw_material_id !== 'number' || raw_material_id <= 0) {
        const error = new Error('Geçerli bir hammadde/yarı mamul ID\'si gereklidir.');
        error.status = 400;
        return next(error);
    }
    if (finished_product_id === raw_material_id) {
        const error = new Error('Bir ürün kendi kendisine hammadde olarak eklenemez.');
        error.status = 400;
        return next(error);
    }
    const parsedQuantity = parseFloat(quantity_required);
    if (isNaN(parsedQuantity) || parsedQuantity <= 0) {
        const error = new Error('Miktar, sıfırdan büyük bir sayı olmalıdır.');
        error.status = 400;
        return next(error);
    }

    try {
        console.log('[POST /api/bill-of-materials] İstek Body:', req.body); // Gelen isteği logla
        console.log('[POST /api/bill-of-materials] Kullanıcı:', { userId, username });

        // 1. Bitmiş ürünün varlığını ve tipini kontrol et (isteğe bağlı ama önerilir)
        const finishedProductCheck = await pool.query('SELECT id, name, product_type FROM products WHERE id = $1', [finished_product_id]);
        if (finishedProductCheck.rows.length === 0) {
            const error = new Error(`Bitmiş ürün ID'si (${finished_product_id}) bulunamadı.`);
            error.status = 404;
            return next(error);
        }
        if (finishedProductCheck.rows[0].product_type !== 'BITMIS_URUN' && finishedProductCheck.rows[0].product_type !== 'YARI_MAMUL') {
            const error = new Error(`ID'si ${finished_product_id} olan ürün (${finishedProductCheck.rows[0].name}), 'BITMIS_URUN' veya 'YARI_MAMUL' tipinde olmalıdır.`);
            error.status = 400;
            return next(error);
        }

        // 2. Hammaddenin varlığını ve tipini kontrol et (isteğe bağlı ama önerilir)
        const rawMaterialCheck = await pool.query('SELECT id, name, product_type FROM products WHERE id = $1', [raw_material_id]);
        if (rawMaterialCheck.rows.length === 0) {
            const error = new Error(`Hammadde ID'si (${raw_material_id}) bulunamadı.`);
            error.status = 404;
            return next(error);
        }
        if (rawMaterialCheck.rows[0].product_type !== 'HAMMADDE' && rawMaterialCheck.rows[0].product_type !== 'YARI_MAMUL') {
            const error = new Error(`ID'si ${raw_material_id} olan ürün (${rawMaterialCheck.rows[0].name}), 'HAMMADDE' veya 'YARI_MAMUL' tipinde olmalıdır.`);
            error.status = 400;
            return next(error);
        }


        const existingEntry = await pool.query(
            'SELECT id FROM bill_of_materials WHERE finished_product_id = $1 AND raw_material_id = $2',
            [finished_product_id, raw_material_id]
        );

        if (existingEntry.rows.length > 0) {
            console.warn('[POST /api/bill-of-materials] Çakışma: Bu hammadde zaten bu ürünün reçetesinde mevcut.');
            const error = new Error('Bu hammadde zaten bu ürünün reçetesinde mevcut. Miktarı güncellemek için PUT isteği kullanın.');
            error.status = 409; // Conflict
            return next(error);
        }

        const insertQuery = 'INSERT INTO bill_of_materials (finished_product_id, raw_material_id, quantity_required) VALUES ($1, $2, $3) RETURNING *';
        const queryParams = [finished_product_id, raw_material_id, parsedQuantity];
        
        console.log('[POST /api/bill-of-materials] SQL Sorgusu:', insertQuery);
        console.log('[POST /api/bill-of-materials] Sorgu Parametreleri:', queryParams);

        const result = await pool.query(insertQuery, queryParams);

        console.log('[POST /api/bill-of-materials] Veritabanı Sonucu:', { 
            rowCount: result.rowCount, 
            rows: result.rows // RETURNING * ile dönen satırları logla
        });

        if (result.rowCount === 0 || !result.rows || result.rows.length === 0) {
            console.error('[POST /api/bill-of-materials] HATA: Veritabanına kayıt eklenemedi veya eklenen kayıt geri DÖNMEDİ. `result.rows` boş.');
            const error = new Error('Reçete kalemi veritabanına eklendi ancak sonuç alınamadı. Lütfen kayıtları kontrol edin.');
            error.status = 500; 
            return next(error); 
        }

        console.log('[POST /api/bill-of-materials] Başarıyla eklendi, ID:', result.rows[0].id);
        await logAudit(userId, username, 'CREATE_BOM_ITEM', 'bill_of_materials', result.rows[0].id, null, result.rows[0]);
        res.status(201).json({ message: 'Reçete kalemi başarıyla eklendi.', bom_item: result.rows[0] });

    } catch (err) {
        console.error('--- [POST /api/bill-of-materials] CATCH BLOGU HATA DETAYLARI ---');
        console.error('Zaman:', new Date().toISOString());
        console.error('İstek Body:', req.body);
        console.error('Kullanıcı:', req.user ? { id: req.user.id, username: req.user.username } : 'Bulunamadı');
        console.error('Hata Mesajı:', err.message);
        console.error('Hata Kodu (varsa):', err.code); 
        console.error('Hata Detayı (varsa):', err.detail); 
        console.error('Hata Stack Trace:\n', err.stack);
        console.error('--- HATA DETAYLARI SONU ---');

        if (err.code === '23503') { // foreign_key_violation
             // Hangi foreign key'in ihlal edildiğini anlamak için err.constraint ve err.detail kullanılabilir
            console.error('[POST /api/bill-of-materials] Foreign Key İhlali:', err.constraint, err.detail);
            const fkError = new Error(`Referans hatası: ${err.detail || 'Belirtilen bitmiş ürün veya hammadde ID\'si geçerli değil.'}`);
            fkError.status = 400; 
            return next(fkError);
        }
        if (err.code === '23505') { // unique_violation
            console.warn('[POST /api/bill-of-materials] Unique Constraint İhlali:', err.constraint, err.detail);
            const uniqueError = new Error('Bu hammadde zaten bu ürünün reçetesinde mevcut (unique constraint).');
            uniqueError.status = 409;
            return next(uniqueError);
        }
        // Diğer veya bilinmeyen veritabanı hataları için
        if (err.code) { // err.code varsa, muhtemelen veritabanı hatasıdır
             const dbError = new Error(`Veritabanı hatası oluştu: ${err.message} (Kod: ${err.code})`);
             dbError.status = 500;
             return next(dbError);
        }

        // Eğer hata `Error` nesnesi olarak fırlatılmışsa ve `status`u varsa onu kullan
        if (err.status) {
            return next(err);
        }

        // Diğer tüm durumlar için genel sunucu hatası
        const error = new Error(`Reçete kalemi eklenirken beklenmedik bir sunucu hatası oluştu.`);
        error.status = 500;
        next(error);
    }
});

// Bir Ürünün Reçetesini Getir (YETKİLENDİRME GEÇİCİ OLARAK SADECE TOKEN - SONRA GÜNCELLENECEK!)
app.get('/api/bill-of-materials/:finished_product_id', authenticateToken, async (req, res, next) => {
    const { finished_product_id } = req.params;

    // Validasyon
    if (isNaN(parseInt(finished_product_id)) || parseInt(finished_product_id) <= 0) {
        const error = new Error('Geçerli bir bitmiş ürün ID\'si gereklidir.');
        error.status = 400;
        return next(error);
    }

    try {
        const query = `
            SELECT
                bom.id AS bom_item_id,
                bom.raw_material_id AS raw_material_product_id,
                p_raw.name AS raw_material_name,
                p_raw.barcode AS raw_material_barcode,
                p_raw.unit_of_measure AS raw_material_unit_of_measure,
                bom.quantity_required
            FROM
                bill_of_materials bom
            JOIN
                products p_raw ON bom.raw_material_id = p_raw.id
            WHERE
                bom.finished_product_id = $1
            ORDER BY
                p_raw.name ASC;
        `;
        const { rows } = await pool.query(query, [finished_product_id]);

        if (rows.length === 0) {
            // Reçete bulunamadı ama bu bir hata değil, boş bir array dönebiliriz.
            // Veya isteğe bağlı olarak 404 de döndürebilirsiniz. Şimdilik boş array.
            return res.json([]);
        }

        res.json(rows);
    } catch (err) {
        next(err);
    }
});

// Bir Reçete Kalemini Güncelle (Miktarını Değiştir)
app.put('/api/bill-of-materials/:id', authenticateToken, /* isUretimOrAdmin, */ async (req, res, next) => {
    const { id } = req.params; // Güncellenecek reçete kaleminin ID'si (bom_item_id)
    const { quantity_required } = req.body;
    const userId = req.user.id;
    const username = req.user.username;

    console.log(`[PUT /api/bill-of-materials/${id}] İstek Body:`, req.body);
    console.log(`[PUT /api/bill-of-materials/${id}] Kullanıcı:`, { userId, username });

    // ID Validasyonu
    const itemId = parseInt(id);
    if (isNaN(itemId) || itemId <= 0) {
        const error = new Error('Geçersiz reçete kalemi ID formatı.');
        error.status = 400;
        return next(error);
    }

    // Miktar Validasyonu
    if (typeof quantity_required === 'undefined') {
        const error = new Error('Güncellemek için "quantity_required" alanı zorunludur.');
        error.status = 400;
        return next(error);
    }
    const parsedQuantity = parseFloat(quantity_required);
    if (isNaN(parsedQuantity) || parsedQuantity <= 0) {
        const error = new Error('Gerekli miktar (quantity_required) pozitif bir sayı olmalıdır.');
        error.status = 400;
        return next(error);
    }

    try {
        // Önce mevcut kaydı (eski değeri) alalım (audit log ve varlık kontrolü için)
        const existingItemResult = await pool.query('SELECT * FROM bill_of_materials WHERE id = $1', [itemId]);

        if (existingItemResult.rows.length === 0) {
            console.warn(`[PUT /api/bill-of-materials/${itemId}] Reçete kalemi bulunamadı.`);
            const error = new Error('Güncellenecek reçete kalemi bulunamadı.');
            error.status = 404; // Not Found
            return next(error);
        }
        const oldBomItem = existingItemResult.rows[0];

        // Güncelleme sorgusu
        const updateQuery = `
            UPDATE bill_of_materials 
            SET quantity_required = $1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $2 
            RETURNING *
        `;
        const queryParams = [parsedQuantity, itemId];

        console.log(`[PUT /api/bill-of-materials/${itemId}] SQL Sorgusu:`, updateQuery);
        console.log(`[PUT /api/bill-of-materials/${itemId}] Sorgu Parametreleri:`, queryParams);

        const result = await pool.query(updateQuery, queryParams);
        
        console.log(`[PUT /api/bill-of-materials/${itemId}] Veritabanı Sonucu:`, { 
            rowCount: result.rowCount, 
            rows: result.rows 
        });

        if (result.rowCount === 0 || !result.rows || result.rows.length === 0) {
            // Bu durum, varlık kontrolü yapıldığı için normalde olmamalı.
            console.error(`[PUT /api/bill-of-materials/${itemId}] HATA: Kayıt güncellenemedi veya güncellenen kayıt geri DÖNMEDİ.`);
            const error = new Error('Reçete kalemi güncellendi ancak sonuç alınamadı.');
            error.status = 500;
            return next(error);
        }

        console.log(`[PUT /api/bill-of-materials/${itemId}] Başarıyla güncellendi, ID:`, result.rows[0].id);
        await logAudit(userId, username, 'UPDATE_BOM_ITEM', 'bill_of_materials', itemId, oldBomItem, result.rows[0]);
        
        res.status(200).json({ message: 'Reçete kalemi başarıyla güncellendi.', bom_item: result.rows[0] });

    } catch (err) {
        console.error(`--- [PUT /api/bill-of-materials/${id}] CATCH BLOGU HATA DETAYLARI ---`);
        console.error('Zaman:', new Date().toISOString());
        console.error('İstek Body:', req.body);
        console.error('Kullanıcı:', req.user ? { id: req.user.id, username: req.user.username } : 'Bulunamadı');
        console.error('Hata Mesajı:', err.message);
        console.error('Hata Kodu (varsa):', err.code);
        console.error('Hata Detayı (varsa):', err.detail);
        console.error('Hata Stack Trace:\n', err.stack);
        console.error('--- HATA DETAYLARI SONU ---');

        // Eğer hata `Error` nesnesi olarak fırlatılmışsa ve `status`u varsa onu kullan
        if (err.status) {
            return next(err);
        }
        // Veritabanı ile ilgili olabilecek diğer hatalar için
        if (err.code) {
            const dbError = new Error(`Veritabanı hatası oluştu: ${err.message} (Kod: ${err.code})`);
            dbError.status = 500;
            return next(dbError);
        }
        // Genel sunucu hatası
        const error = new Error('Reçete kalemi güncellenirken beklenmedik bir sunucu hatası oluştu.');
        error.status = 500;
        next(error);
    }
});

// Bir Reçete Kalemini Sil
app.delete('/api/bill-of-materials/:id', authenticateToken, /* isUretimOrAdmin, */ async (req, res, next) => {
    const { id } = req.params; // Silinecek reçete kaleminin ID'si (bom_item_id)
    const userId = req.user.id;
    const username = req.user.username;

    console.log(`[DELETE /api/bill-of-materials/${id}] İstek alındı.`);
    console.log(`[DELETE /api/bill-of-materials/${id}] Kullanıcı:`, { userId, username });

    // ID Validasyonu
    const itemId = parseInt(id);
    if (isNaN(itemId) || itemId <= 0) {
        const error = new Error('Geçersiz reçete kalemi ID formatı.');
        error.status = 400;
        return next(error);
    }

    try {
        // Silmeden önce kaydı çekelim ki audit log'a neyin silindiğini yazabilelim
        // ve var olmayan bir şeyi silmeye çalışıp çalışmadığımızı bilelim.
        const selectQuery = 'SELECT * FROM bill_of_materials WHERE id = $1';
        const selectedItem = await pool.query(selectQuery, [itemId]);

        if (selectedItem.rows.length === 0) {
            console.warn(`[DELETE /api/bill-of-materials/${itemId}] Silinecek reçete kalemi bulunamadı.`);
            const error = new Error('Silinecek reçete kalemi bulunamadı.');
            error.status = 404; // Not Found
            return next(error);
        }
        const bomItemToDelete = selectedItem.rows[0]; // Audit log için sakla

        // Silme sorgusu
        const deleteQuery = 'DELETE FROM bill_of_materials WHERE id = $1 RETURNING *';
        const queryParams = [itemId];

        console.log(`[DELETE /api/bill-of-materials/${itemId}] SQL Sorgusu:`, deleteQuery);
        console.log(`[DELETE /api/bill-of-materials/${itemId}] Sorgu Parametreleri:`, queryParams);

        const result = await pool.query(deleteQuery, queryParams);
        
        console.log(`[DELETE /api/bill-of-materials/${itemId}] Veritabanı Sonucu:`, { 
            rowCount: result.rowCount,
            // result.rows burada silinen kaydı içerir, çünkü RETURNING * kullandık
            deletedItem: result.rows && result.rows.length > 0 ? result.rows[0] : null 
        });

        // rowCount 0 ise zaten yukarıdaki varlık kontrolünde yakalanırdı ama yine de bir kontrol.
        if (result.rowCount === 0) {
            // Bu durumun oluşmaması gerek, çünkü yukarıda varlık kontrolü yaptık.
            // Eğer buraya gelinirse, bir race condition veya beklenmedik bir durum var demektir.
            console.error(`[DELETE /api/bill-of-materials/${itemId}] HATA: Kayıt bulunamadığı için silinemedi (beklenmedik durum).`);
            const error = new Error('Reçete kalemi silinemedi (bulunamadı).');
            error.status = 404; // Not Found
            return next(error);
        }

        console.log(`[DELETE /api/bill-of-materials/${itemId}] Başarıyla silindi, ID:`, bomItemToDelete.id);
        // Audit log'a silinen kaydın tamamını (bomItemToDelete) eski değer olarak kaydediyoruz.
        await logAudit(userId, username, 'DELETE_BOM_ITEM', 'bill_of_materials', itemId, bomItemToDelete, null);
        
        // Yanıtta silinen öğeyi de gönderebiliriz.
        res.status(200).json({ message: 'Reçete kalemi başarıyla silindi.', deleted_bom_item: bomItemToDelete });

    } catch (err) {
        console.error(`--- [DELETE /api/bill-of-materials/${id}] CATCH BLOGU HATA DETAYLARI ---`);
        console.error('Zaman:', new Date().toISOString());
        console.error('Kullanıcı:', req.user ? { id: req.user.id, username: req.user.username } : 'Bulunamadı');
        console.error('Hata Mesajı:', err.message);
        console.error('Hata Kodu (varsa):', err.code);
        console.error('Hata Detayı (varsa):', err.detail);
        console.error('Hata Stack Trace:\n', err.stack);
        console.error('--- HATA DETAYLARI SONU ---');

        if (err.status) {
            return next(err);
        }
        if (err.code) { // Veritabanı ile ilgili olabilecek diğer hatalar
            const dbError = new Error(`Veritabanı hatası oluştu: ${err.message} (Kod: ${err.code})`);
            dbError.status = 500;
            return next(dbError);
        }
        const error = new Error('Reçete kalemi silinirken beklenmedik bir sunucu hatası oluştu.');
        error.status = 500;
        next(error);
    }
});

// ------------------- KATEGORİ YÖNETİMİ API'leri -------------------

// Kategori Ekle (Sadece Admin)
app.post('/api/categories', authenticateToken, isAdmin, async (req, res, next) => {
    const { name, description } = req.body;
    if (!name || name.length < 2) {
        const error = new Error('Kategori adı en az 2 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    try {
        const existingCategory = await pool.query('SELECT id FROM categories WHERE name ILIKE $1', [name]);
        if (existingCategory.rows.length > 0) {
            const error = new Error('Bu isimde bir kategori zaten mevcut.');
            error.status = 409; // Conflict
            return next(error);
        }
        const result = await pool.query(
            'INSERT INTO categories (name, description) VALUES ($1, $2) RETURNING *',
            [name, description || null]
        );
        await logAudit(req.user.id, req.user.username, 'CREATE', 'categories', result.rows[0].id, null, result.rows[0]);
        res.status(201).json({ message: 'Kategori başarıyla eklendi.', category: result.rows[0] });
    } catch (err) {
        next(err);
    }
});



// app.js dosyanızda

// Tüm Kategorileri Getir (Sayfalama, Sıralama ve ARAMA EKLENDİ)
app.get('/api/categories', authenticateToken, async (req, res, next) => {
    try {
        let { page = 1, limit = 10, sortBy = 'id', sortOrder = 'asc', search = '' } = req.query; // search parametresi eklendi

        page = parseInt(page);
        limit = parseInt(limit);
        const offset = (page - 1) * limit;

        if (isNaN(page) || page <= 0 || isNaN(limit) || limit <= 0) {
            return next(Object.assign(new Error('Geçersiz sayfa veya limit değeri.'), { status: 400 }));
        }

        const validSortColumns = ['id', 'name', 'description'];
        const validSortOrders = ['asc', 'desc'];

        const column = validSortColumns.includes(sortBy) ? sortBy : 'id';
        const order = validSortOrders.includes(sortOrder) ? sortOrder : 'asc';

        let queryParams = [];
        let whereClauses = [];
        let paramIndex = 1; // SQL sorgusundaki parametreler için sayaç ($1, $2 ...)

        if (search && search.trim() !== "") {
            const searchTerm = `%${search.trim().toLowerCase()}%`; // ILIKE için küçük harf ve wildcard
            whereClauses.push(`(LOWER(name) ILIKE $${paramIndex} OR LOWER(description) ILIKE $${paramIndex})`);
            queryParams.push(searchTerm);
            // countQueryParams için ayrıca bir dizi tutmaya gerek yok, aynı queryParams'ı kullanabiliriz (limit ve offset hariç)
            paramIndex++;
        }

        const whereCondition = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        // Kategorileri getiren ana sorgu
        const categoriesQuery = `SELECT * FROM categories ${whereCondition} ORDER BY ${column} ${order} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        const finalQueryParamsForSelect = [...queryParams, limit, offset]; // Arama parametreleri + limit + offset

        // Toplam kategori sayısını getiren sorgu (arama filtresiyle birlikte)
        const countQuery = `SELECT COUNT(*) FROM categories ${whereCondition}`;
        // countQuery için queryParams'ın sadece arama ile ilgili kısımları kullanılır (limit/offset olmadan)
        const finalQueryParamsForCount = [...queryParams];


        console.log('Categories Query:', categoriesQuery, finalQueryParamsForSelect); // DEBUG
        console.log('Count Query:', countQuery, finalQueryParamsForCount); // DEBUG

        const categoriesResult = await pool.query(categoriesQuery, finalQueryParamsForSelect);
        const countResult = await pool.query(countQuery, finalQueryParamsForCount);

        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit) || 1; // totalItems 0 ise totalPages 1 olsun

        res.json({
            categories: categoriesResult.rows,
            currentPage: page,
            totalPages: totalPages,
            totalItems: totalItems
        });
    } catch (err) {
        console.error('Kategoriler getirilirken hata:', err); // Hata logunu iyileştir
        next(err);
    }
});


// ------------------- BİRİM YÖNETİMİ API'leri -------------------

// app.js dosyanızda

// Tüm Birimleri Getir (Sayfalama, Sıralama ve ARAMA EKLENDİ)
app.get('/api/units', authenticateToken, async (req, res, next) => {
    try {
        let { page = 1, limit = 10, sortBy = 'id', sortOrder = 'asc', search = '' } = req.query; // search parametresi eklendi

        page = parseInt(page);
        limit = parseInt(limit);
        const offset = (page - 1) * limit;

        if (isNaN(page) || page <= 0 || isNaN(limit) || limit <= 0) {
            return next(Object.assign(new Error('Geçersiz sayfa veya limit değeri.'), { status: 400 }));
        }

        const validSortColumns = ['id', 'name', 'abbreviation', 'created_at'];
        const validSortOrders = ['asc', 'desc'];

        const column = validSortColumns.includes(sortBy) ? sortBy : 'id';
        const order = validSortOrders.includes(sortOrder) ? sortOrder : 'asc';

        let queryParams = [];
        let whereClauses = [];
        let paramIndex = 1;

        if (search && search.trim() !== "") {
            const searchTerm = `%${search.trim().toLowerCase()}%`;
            whereClauses.push(`(LOWER(name) ILIKE $${paramIndex} OR LOWER(abbreviation) ILIKE $${paramIndex})`);
            queryParams.push(searchTerm);
            paramIndex++;
        }

        const whereCondition = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        const unitsQuery = `SELECT id, name, abbreviation, created_at FROM units ${whereCondition} ORDER BY ${column} ${order} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        const finalQueryParamsForSelect = [...queryParams, limit, offset];

        const countQuery = `SELECT COUNT(*) FROM units ${whereCondition}`;
        const finalQueryParamsForCount = [...queryParams];
        
        console.log('Units Query:', unitsQuery, finalQueryParamsForSelect); // DEBUG
        console.log('Units Count Query:', countQuery, finalQueryParamsForCount); // DEBUG

        const unitsResult = await pool.query(unitsQuery, finalQueryParamsForSelect);
        const countResult = await pool.query(countQuery, finalQueryParamsForCount);

        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit) || 1;

        res.json({
            units: unitsResult.rows,
            currentPage: page,
            totalPages: totalPages,
            totalItems: totalItems
        });
    } catch (err) {
        console.error('Birimler getirilirken hata:', err); // Hata logunu iyileştir
        next(err);
    }
});




// Yeni Birim Ekle (Sadece Admin rolü için - isUretimOrAdmin vs. gibi kendi rolünüze göre değiştirebilirsiniz)
app.post('/api/units', authenticateToken, isAdmin, async (req, res, next) => {
    const { name, abbreviation } = req.body;
    if (!name || name.trim().length < 1) {
        return next(Object.assign(new Error('Birim adı en az 1 karakter olmalıdır.'), { status: 400 }));
    }
    if (!abbreviation || abbreviation.trim().length < 1) {
        return next(Object.assign(new Error('Birim kısaltması en az 1 karakter olmalıdır.'), { status: 400 }));
    }

    try {
        const existingUnitByName = await pool.query('SELECT id FROM units WHERE name ILIKE $1', [name.trim()]);
        if (existingUnitByName.rows.length > 0) {
            return next(Object.assign(new Error('Bu isimde bir birim zaten mevcut.'), { status: 409 }));
        }
        const existingUnitByAbbr = await pool.query('SELECT id FROM units WHERE abbreviation ILIKE $1', [abbreviation.trim()]);
        if (existingUnitByAbbr.rows.length > 0) {
            return next(Object.assign(new Error('Bu kısaltmaya sahip bir birim zaten mevcut.'), { status: 409 }));
        }

        const result = await pool.query(
            'INSERT INTO units (name, abbreviation) VALUES ($1, $2) RETURNING *',
            [name.trim(), abbreviation.trim()]
        );
        await logAudit(req.user.id, req.user.username, 'CREATE', 'units', result.rows[0].id, null, result.rows[0]);
        res.status(201).json({ message: 'Birim başarıyla eklendi.', unit: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') { // Unique violation
            return next(Object.assign(new Error('Bu birim adı veya kısaltması zaten mevcut.'), { status: 409 }));
        }
        next(err);
    }
});

// Birim Güncelle (Sadece Admin)
app.put('/api/units/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    const { name, abbreviation } = req.body;

    if (!name || name.trim().length < 1) {
        return next(Object.assign(new Error('Birim adı en az 1 karakter olmalıdır.'), { status: 400 }));
    }
    if (!abbreviation || abbreviation.trim().length < 1) {
        return next(Object.assign(new Error('Birim kısaltması en az 1 karakter olmalıdır.'), { status: 400 }));
    }
    const unitId = parseInt(id);
    if (isNaN(unitId) || unitId <= 0) {
         return next(Object.assign(new Error('Geçersiz birim IDsi.'), { status: 400 }));
    }

    try {
        const oldUnitResult = await pool.query('SELECT * FROM units WHERE id = $1', [unitId]);
        if (oldUnitResult.rows.length === 0) {
            return next(Object.assign(new Error('Birim bulunamadı.'), { status: 404 }));
        }
        const oldUnit = oldUnitResult.rows[0];

        const existingUnitByName = await pool.query('SELECT id FROM units WHERE name ILIKE $1 AND id != $2', [name.trim(), unitId]);
        if (existingUnitByName.rows.length > 0) {
            return next(Object.assign(new Error('Bu isimde başka bir birim zaten mevcut.'), { status: 409 }));
        }
        const existingUnitByAbbr = await pool.query('SELECT id FROM units WHERE abbreviation ILIKE $1 AND id != $2', [abbreviation.trim(), unitId]);
        if (existingUnitByAbbr.rows.length > 0) {
            return next(Object.assign(new Error('Bu kısaltmaya sahip başka bir birim zaten mevcut.'), { status: 409 }));
        }

        const result = await pool.query(
            'UPDATE units SET name = $1, abbreviation = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *',
            [name.trim(), abbreviation.trim(), unitId]
        );
        await logAudit(req.user.id, req.user.username, 'UPDATE', 'units', unitId, oldUnit, result.rows[0]);
        res.json({ message: 'Birim başarıyla güncellendi.', unit: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') { 
            return next(Object.assign(new Error('Bu birim adı veya kısaltması zaten mevcut (başka bir kayıtta).'), { status: 409 }));
        }
        next(err);
    }
});

// Birim Sil (Sadece Admin)
app.delete('/api/units/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    const unitId = parseInt(id);
    if (isNaN(unitId) || unitId <= 0) {
         return next(Object.assign(new Error('Geçersiz birim IDsi.'), { status: 400 }));
    }

    try {
        const unitToDeleteResult = await pool.query('SELECT * FROM units WHERE id = $1', [unitId]);
        if (unitToDeleteResult.rows.length === 0) {
            return next(Object.assign(new Error('Birim bulunamadı.'), { status: 404 }));
        }
        const unitToDelete = unitToDeleteResult.rows[0];

        // ÖNEMLİ: Bu birime bağlı ürün var mı kontrol et.
        // products tablosundaki unit_of_measure alanı bu birimin KISALTMASINI veya ADINI tutuyor.
        // Bu yüzden, unitToDelete.abbreviation veya unitToDelete.name ile kontrol yapın.
        // Hangi alanı (kısaltma mı, tam ad mı) products.unit_of_measure'da sakladığınıza bağlı.
        // Ben kısaltmayı (abbreviation) varsayıyorum:
        const productCountResult = await pool.query('SELECT COUNT(*) FROM products WHERE unit_of_measure = $1', [unitToDelete.abbreviation]);
        const productCount = parseInt(productCountResult.rows[0].count);

        if (productCount > 0) {
            return next(Object.assign(new Error(`Bu ölçü birimi ("${unitToDelete.name}") ${productCount} üründe kullanıldığı için silinemez.`), { status: 400 }));
        }

        const result = await pool.query('DELETE FROM units WHERE id = $1 RETURNING *', [unitId]);
        // result.rows[0] artık silindiği için unitToDelete'i kullanmak daha iyi.
        await logAudit(req.user.id, req.user.username, 'DELETE', 'units', unitId, unitToDelete, null);
        res.json({ message: 'Birim başarıyla silindi.', unit: unitToDelete });
    } catch (err) {
        next(err);
    }
});

// ------------------- BİRİM YÖNETİMİ API'leri SONU -------------------


// -------------------------------------------------------------
// YENİ: SEVKİYAT SİPARİŞLERİ API ROTLARI
// -------------------------------------------------------------

// Yeni Sevkiyat Siparişi Oluşturma
// authenticateToken middleware'ini ve gerekirse rol kontrolü (örn: isSevkiyatOrAdmin) ekleyebilirsiniz.
// -------------------------------------------------------------
// YENİ: SEVKİYAT SİPARİŞLERİ API ROTLARI (GÜNCELLENMİŞ)
// -------------------------------------------------------------

// Yeni Sevkiyat Siparişi Oluşturma
// authenticateToken middleware'ini ve gerekirse rol kontrolü (örn: isSevkiyatOrAdmin) ekleyebilirsiniz.
app.post('/api/sevkiyat-siparisleri', authenticateToken, checkPermission('sevkiyat_siparisi_olustur'),/* opsiyonelRolKontrolu, */ async (req, res, next) => {
    // 1. İstek body'sinden verileri al (siparis_no kullanıcıdan gelmeyecek)
    const { kabin_kodu, firma_id, referans_bina, genel_notlar } = req.body;
    const user_id = req.user.id; // authenticateToken'dan gelir
    const username = req.user.username; // audit log için

    // 2. Temel Giriş Doğrulaması
    if (!kabin_kodu || !firma_id) { // kabin_kodu hala zorunlu bir referans olarak girilecek
        const error = new Error('Kabin kodu ve Firma ID zorunludur.');
        error.status = 400; // Bad Request
        return next(error);
    }

    try {
        // 3. Yeni ve benzersiz sipariş numarasını (siparis_no) üret
        // 'SIPO' ön ekini veya kendi belirleyeceğiniz bir ön eki kullanabilirsiniz.
        // Bu fonksiyonun (generateTransactionCode) app.js dosyanızda tanımlı olduğunu varsayıyorum.
        const yeni_siparis_no = await generateTransactionCode('SIPSV'); 

        // 4. Veritabanına yeni kayıt ekle
        const insertQuery = `
            INSERT INTO sevkiyat_siparisleri 
                (siparis_no, kabin_kodu, firma_id, user_id, referans_bina, genel_notlar, durum, siparis_tarihi)
            VALUES 
                ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
            RETURNING *; 
            -- RETURNING * ile eklenen tüm satırı geri alıyoruz
        `;
        const queryParams = [
            yeni_siparis_no,     // $1 - Sistem tarafından üretilen benzersiz siparis_no
            kabin_kodu,          // $2 - Kullanıcının girdiği, artık benzersiz olması gerekmeyen kabin_kodu
            parseInt(firma_id),  // $3 (firma_id'nin sayı olduğundan emin olalım)
            user_id,             // $4
            referans_bina,       // $5 (null olabilir)
            genel_notlar,        // $6 (null olabilir)
            'Hazırlanıyor'       // $7 (varsayılan durum)
        ];

        const result = await pool.query(insertQuery, queryParams);
        const yeniSiparis = result.rows[0];

        // 5. Audit Log kaydı (opsiyonel ama önerilir)
        // Bu fonksiyonun (logAudit) app.js dosyanızda tanımlı olduğunu varsayıyorum.
        await logAudit(user_id, username, 'CREATE_SEVKIYAT_SIPARISI', 'sevkiyat_siparisleri', yeniSiparis.id, null, yeniSiparis);

        // 6. Başarı mesajı ve oluşturulan kaydı dön
        res.status(201).json({ 
            message: 'Yeni sevkiyat siparişi başarıyla oluşturuldu.', 
            siparis: yeniSiparis 
        });

    } catch (error) {
        // Hata yönetimi
        if (error.code === '23505') { // unique_violation (siparis_no için UNIQUE constraint hatası - çok nadir olmalı)
             error.message = 'Benzersiz sipariş numarası üretilirken sistemsel bir sorun oluştu veya beklenmedik bir çakışma yaşandı. Lütfen tekrar deneyin.';
             error.status = 500; // Veya 409 Conflict
        } else if (error.code === '23503') { // foreign_key_violation (firma_id veya user_id geçersizse)
             error.message = 'Belirtilen firma ID veya kullanıcı ID geçersiz.';
             error.status = 400;
        }
        // Diğer potansiyel veritabanı hataları veya genel hatalar için
        // `next(error)` genel hata yakalayıcınıza yönlendirir.
        next(error);
    }
});



// Mevcut /api/sevkiyat-siparisleri POST rotasından sonra:

// Tüm Sevkiyat Siparişlerini Getirme (Sayfalama, Temel Sıralama ve Filtreleme ile)
app.get('/api/sevkiyat-siparisleri', authenticateToken, checkPermission('sevkiyat_siparisi_goruntule'), async (req, res, next) => {
    try {
        // 1. Query parametrelerinden sayfalama, sıralama ve filtre bilgilerini al
        let { 
            page = 1, 
            limit = 10, 
            sortBy = 'siparis_tarihi', 
            sortOrder = 'DESC',
            firma_id,        // Filtrelemek için firma_id
            kabin_kodu,      // Filtrelemek için kabin_kodu (ILIKE ile arama)
            durum,           // Filtrelemek için durum
            baslangic_tarihi, // Tarih aralığı için başlangıç
            bitis_tarihi      // Tarih aralığı için bitiş
        } = req.query;

        page = parseInt(page);
        limit = parseInt(limit);
        const offset = (page - 1) * limit;

        // Güvenli sıralama sütunları listesi
        const gecerliSortByAlanlari = ['id', 'siparis_no', 'kabin_kodu', 'siparis_tarihi', 'durum', 'firma_adi']; // firma_adi için JOIN gerekecek
        const gecerliSortOrderTipleri = ['ASC', 'DESC'];

        const finalSortBy = gecerliSortByAlanlari.includes(sortBy) ? sortBy : 'siparis_tarihi';
        const finalSortOrder = gecerliSortOrderTipleri.includes(sortOrder.toUpperCase()) ? sortOrder.toUpperCase() : 'DESC';
        
        // JOIN'li sorgularda sıralama için sütun adlarını tablo adlarıyla belirtmek gerekebilir.
        // Örneğin, sortBy 'firma_adi' ise SQL'de c.name gibi.
        let orderByClause = `ORDER BY ss.${finalSortBy === 'firma_adi' ? 'firma_id' : finalSortBy} ${finalSortOrder}`; // Basit bir örnek, firma_adi için ss.firma_id kullandım, JOIN ile c.name kullanılabilir.

        // Filtreleme için WHERE koşullarını ve parametrelerini oluştur
        let whereClauses = [];
        let queryParams = [];
        let paramIndex = 1;

        if (firma_id) {
            whereClauses.push(`ss.firma_id = $${paramIndex++}`);
            queryParams.push(parseInt(firma_id));
        }
        if (kabin_kodu) {
            whereClauses.push(`LOWER(ss.kabin_kodu) ILIKE $${paramIndex++}`);
            queryParams.push(`%${kabin_kodu.toLowerCase()}%`);
        }
        if (durum) {
            whereClauses.push(`ss.durum = $${paramIndex++}`);
            queryParams.push(durum);
        }
        if (baslangic_tarihi) {
            whereClauses.push(`DATE(ss.siparis_tarihi) >= $${paramIndex++}`);
            queryParams.push(baslangic_tarihi);
        }
        if (bitis_tarihi) {
            whereClauses.push(`DATE(ss.siparis_tarihi) <= $${paramIndex++}`);
            queryParams.push(bitis_tarihi);
        }

        const whereCondition = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        // 2. Veritabanından kayıtları çek (JOIN'ler ile)
        // Ana sorgu (firmalar ve kullanıcılar tablosuyla JOIN)
        // Eğer firma_adi'na göre sıralama yapılacaksa SELECT'e c.name AS firma_adi eklenmeli ve ORDER BY c.name olmalı.
        // Şimdilik basit tutuyorum, firma_adi yerine firma_id görünecek. İsterseniz JOIN ekleyebiliriz.
        const siparislerQuery = `
            SELECT 
                ss.id, 
                ss.siparis_no, 
                ss.kabin_kodu, 
                c.name AS firma_adi,  -- Firmalar tablosundan firma adını alıyoruz
                u.username AS olusturan_kullanici, -- Kullanıcılar tablosundan kullanıcı adını alıyoruz
                ss.siparis_tarihi, 
                ss.referans_bina, 
                ss.durum, 
                ss.genel_notlar,
                ss.created_at,
                ss.updated_at
            FROM sevkiyat_siparisleri ss
            LEFT JOIN companies c ON ss.firma_id = c.id
            LEFT JOIN users u ON ss.user_id = u.id
            ${whereCondition}
            ${orderByClause} -- ORDER BY ss.siparis_tarihi DESC gibi
            LIMIT $${paramIndex++} OFFSET $${paramIndex++};
        `;
        // LIMIT ve OFFSET için queryParams'a değerleri ekle
        const finalSelectParams = [...queryParams, limit, offset];


        // Toplam kayıt sayısını almak için sorgu (filtrelerle birlikte)
        const countQuery = `
            SELECT COUNT(*) 
            FROM sevkiyat_siparisleri ss 
            ${whereCondition};
        `;
        // countQuery için sadece filtre parametreleri kullanılır (limit/offset olmadan)
        const finalCountParams = [...queryParams.slice(0, paramIndex - 3)]; // limit ve offset parametrelerini çıkar


        const siparislerResult = await pool.query(siparislerQuery, finalSelectParams);
        const countResult = await pool.query(countQuery, finalCountParams);

        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit);

        // 3. Yanıtı dön
        res.json({
            siparisler: siparislerResult.rows,
            currentPage: page,
            totalPages: totalPages,
            totalItems: totalItems,
            limit: limit
        });

    } catch (error) {
        next(error);
    }
});


// app.js dosyanızda, diğer /api/sevkiyat-siparisleri rotalarından sonra:

// Belirli Bir Sevkiyat Siparişine Yeni Ürün Kalemi Ekleme
app.post('/api/sevkiyat-siparisleri/:siparisId/kalemler', authenticateToken, checkPermission('sevkiyat_siparisi_duzenle'),  async (req, res, next) => {
    const { siparisId } = req.params; // URL'den ana siparişin ID'sini al
    const { urun_id, miktar, birim, seri_numarasi, kalem_ozel_notlari } = req.body; // Eklenecek kalemin bilgileri
    const user_id = req.user.id; // İşlemi yapan kullanıcı (audit log için)
    const username = req.user.username; // İşlemi yapan kullanıcı (audit log için)

    // Gelen ID'lerin ve miktarın geçerliliğini kontrol et
    if (isNaN(parseInt(siparisId)) || isNaN(parseInt(urun_id))) {
        const error = new Error('Geçersiz sipariş ID veya ürün ID formatı.');
        error.status = 400;
        return next(error);
    }
    const parsedMiktar = parseFloat(miktar);
    if (isNaN(parsedMiktar) || parsedMiktar <= 0) {
        const error = new Error('Miktar pozitif bir sayı olmalıdır.');
        error.status = 400;
        return next(error);
    }
    if (!birim || birim.trim() === '') {
        const error = new Error('Birim boş olamaz.');
        error.status = 400;
        return next(error);
    }

    let client; // try bloğunun dışında tanımla ki finally'de erişilebilsin

    try {
        client = await pool.connect(); // Havuzdan bir istemci al
        await client.query('BEGIN'); // Transaction başlat

        // 1. Ana siparişin varlığını ve durumunu kontrol et
        const siparisCheckQuery = `
            SELECT id, durum 
            FROM sevkiyat_siparisleri 
            WHERE id = $1 FOR UPDATE; 
            -- FOR UPDATE ile satırı kilitle, aynı anda başka bir işlem bu siparişi değiştirmesin
        `;
        const siparisCheckResult = await client.query(siparisCheckQuery, [parseInt(siparisId)]);

        if (siparisCheckResult.rows.length === 0) {
            await client.query('ROLLBACK'); // Hata durumunda transaction'ı geri al
            const error = new Error('Ana sevkiyat siparişi bulunamadı.');
            error.status = 404;
            return next(error);
        }

        const anaSiparis = siparisCheckResult.rows[0];
        // Sadece 'Hazırlanıyor' veya 'Düzeltiliyor' durumundaki siparişlere kalem eklenebilsin (örnek kural)
        if (anaSiparis.durum !== 'Hazırlanıyor' && anaSiparis.durum !== 'Düzeltiliyor') {
            await client.query('ROLLBACK');
            const error = new Error(`Siparişin durumu (${anaSiparis.durum}) kalem eklemeye uygun değil.`);
            error.status = 403; // Forbidden
            return next(error);
        }

        // 2. Ürünün varlığını products tablosunda kontrol et (opsiyonel ama iyi bir pratik)
        const urunCheckQuery = 'SELECT id FROM products WHERE id = $1';
        const urunCheckResult = await client.query(urunCheckQuery, [parseInt(urun_id)]);
        if (urunCheckResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Eklenecek ürün bulunamadı.');
            error.status = 404;
            return next(error);
        }
        
        // 3. Yeni ürün kalemini sevkiyat_siparisi_kalemleri tablosuna ekle
        const insertKalemQuery = `
            INSERT INTO sevkiyat_siparisi_kalemleri
                (sevkiyat_siparisi_id, urun_id, miktar, birim, seri_numarasi, kalem_ozel_notlari)
            VALUES
                ($1, $2, $3, $4, $5, $6)
            RETURNING *;
        `;
        const kalemParams = [
            parseInt(siparisId),
            parseInt(urun_id),
            parsedMiktar,
            birim,
            seri_numarasi, // null olabilir
            kalem_ozel_notlari // null olabilir
        ];
        const kalemResult = await client.query(insertKalemQuery, kalemParams);
        const yeniKalem = kalemResult.rows[0];

        // 4. Ana siparişin updated_at alanını güncelle (trigger yoksa manuel)
        // Eğer sevkiyat_siparisleri için updated_at trigger'ınız varsa bu satıra gerek yok.
        // await client.query('UPDATE sevkiyat_siparisleri SET updated_at = CURRENT_TIMESTAMP WHERE id = $1', [parseInt(siparisId)]);

        // 5. Audit Log
        await logAudit(user_id, username, 'CREATE_SEVKIYAT_KALEMI', 'sevkiyat_siparisi_kalemleri', yeniKalem.id, null, yeniKalem);
        
        await client.query('COMMIT'); // Her şey yolundaysa transaction'ı onayla

        res.status(201).json({
            message: 'Sevkiyat siparişine yeni ürün kalemi başarıyla eklendi.',
            kalem: yeniKalem
        });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK'); // Herhangi bir hata olursa transaction'ı geri al
        }
        // Hata yönetimi (özellikle foreign key ihlalleri)
        if (error.code === '23503') { 
             error.message = 'Belirtilen sevkiyat siparişi ID veya ürün ID geçersiz.';
             error.status = 400;
        }
        next(error);
    } finally {
        if (client) {
            client.release(); // İstemciyi havuza geri bırak
        }
    }
});


// app.js dosyanızda, diğer sevkiyat siparişi rotalarından sonra:

// Belirli Bir Sevkiyat Siparişine Ait Tüm Kalemleri Listeleme
app.get('/api/sevkiyat-siparisleri/:siparisId/kalemler', authenticateToken,checkPermission('sevkiyat_siparisi_goruntule'), async (req, res, next) => {
    const { siparisId } = req.params; // URL'den ana siparişin ID'sini al

    // siparisId'nin geçerli bir sayı olup olmadığını kontrol et
    if (isNaN(parseInt(siparisId))) {
        const error = new Error('Geçersiz sipariş ID formatı.');
        error.status = 400;
        return next(error);
    }

    try {
        // Önce ana siparişin var olup olmadığını kontrol edebiliriz (opsiyonel ama iyi bir pratik)
        const siparisCheckQuery = 'SELECT id FROM sevkiyat_siparisleri WHERE id = $1';
        const siparisCheckResult = await pool.query(siparisCheckQuery, [parseInt(siparisId)]);

        if (siparisCheckResult.rows.length === 0) {
            const error = new Error('Ana sevkiyat siparişi bulunamadı.');
            error.status = 404; // Not Found
            return next(error);
        }

        // Ana sipariş varsa, şimdi kalemlerini çekelim
        const kalemlerQuery = `
            SELECT 
                sk.id AS kalem_id,
                sk.urun_id,
                p.name AS urun_adi,         -- Ürünler tablosundan ürün adı
                p.barcode AS urun_barkodu,  -- Ürünler tablosundan barkod
                sk.miktar,
                sk.birim,
                sk.seri_numarasi,
                sk.kalem_ozel_notlari,
                sk.created_at AS kalem_eklenme_tarihi,
                sk.updated_at AS kalem_guncellenme_tarihi
            FROM sevkiyat_siparisi_kalemleri sk
            JOIN products p ON sk.urun_id = p.id
            WHERE sk.sevkiyat_siparisi_id = $1
            ORDER BY sk.id ASC; -- Kalemleri eklenme sırasına göre veya ürün adına göre sıralayabilirsiniz
        `;
        const kalemlerResult = await pool.query(kalemlerQuery, [parseInt(siparisId)]);

        // Kalemler bulunsa da bulunmasa da (boş liste dönebilir) 200 OK ile yanıt ver
        res.json({ kalemler: kalemlerResult.rows });

    } catch (error) {
        next(error);
    }
});


// app.js dosyanızda, diğer kalem API rotalarından sonra veya uygun bir yere:

// Belirli Bir Sevkiyat Siparişi Kalemini Güncelleme
app.put('/api/sevkiyat-siparisleri/:siparisId/kalemler/:kalemId', authenticateToken,checkPermission('sevkiyat_siparisi_duzenle'), async (req, res, next) => {
    const { siparisId, kalemId } = req.params;
    const { miktar, birim, seri_numarasi, kalem_ozel_notlari } = req.body; // Güncellenecek alanlar
    const user_id = req.user.id; // İşlemi yapan kullanıcı (audit log için)
    const username = req.user.username; // İşlemi yapan kullanıcı (audit log için)

    // ID'lerin geçerliliğini kontrol et
    if (isNaN(parseInt(siparisId)) || isNaN(parseInt(kalemId))) {
        const error = new Error('Geçersiz sipariş ID veya kalem ID formatı.');
        error.status = 400;
        return next(error);
    }

    // Güncellenecek en az bir alan olmalı (isteğe bağlı kontrol)
    if (miktar === undefined && birim === undefined && seri_numarasi === undefined && kalem_ozel_notlari === undefined) {
        const error = new Error('Güncellemek için en az bir alan gönderilmelidir.');
        error.status = 400;
        return next(error);
    }
    
    // Miktar kontrolü (eğer gönderildiyse)
    let parsedMiktar;
    if (miktar !== undefined) {
        parsedMiktar = parseFloat(miktar);
        if (isNaN(parsedMiktar) || parsedMiktar <= 0) {
            const error = new Error('Miktar pozitif bir sayı olmalıdır.');
            error.status = 400;
            return next(error);
        }
    }
    // Birim kontrolü (eğer gönderildiyse)
    if (birim !== undefined && (birim === null || birim.trim() === '')) {
        const error = new Error('Birim boş olamaz.');
        error.status = 400;
        return next(error);
    }


    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        // 1. Ana siparişin varlığını ve durumunu kontrol et
        const siparisCheckQuery = 'SELECT durum FROM sevkiyat_siparisleri WHERE id = $1 FOR UPDATE';
        const siparisCheckResult = await client.query(siparisCheckQuery, [parseInt(siparisId)]);

        if (siparisCheckResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Ana sevkiyat siparişi bulunamadı.');
            error.status = 404;
            return next(error);
        }
        const anaSiparisDurumu = siparisCheckResult.rows[0].durum;
        if (anaSiparisDurumu !== 'Hazırlanıyor' && anaSiparisDurumu !== 'Düzeltiliyor') {
            await client.query('ROLLBACK');
            const error = new Error(`Siparişin durumu (${anaSiparisDurumu}) kalem güncellemeye uygun değil.`);
            error.status = 403; // Forbidden
            return next(error);
        }

        // 2. Güncellenecek kalemin varlığını ve doğru siparişe ait olduğunu kontrol et, eski değerleri al (audit için)
        const kalemCheckQuery = 'SELECT * FROM sevkiyat_siparisi_kalemleri WHERE id = $1 AND sevkiyat_siparisi_id = $2 FOR UPDATE';
        const kalemCheckResult = await client.query(kalemCheckQuery, [parseInt(kalemId), parseInt(siparisId)]);

        if (kalemCheckResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Güncellenecek ürün kalemi bulunamadı veya belirtilen siparişe ait değil.');
            error.status = 404;
            return next(error);
        }
        const eskiKalem = kalemCheckResult.rows[0];

        // 3. Dinamik UPDATE sorgusu oluştur
        let updateFields = [];
        let updateValues = [];
        let paramIndex = 1;

        if (miktar !== undefined) {
            updateFields.push(`miktar = $${paramIndex++}`);
            updateValues.push(parsedMiktar);
        }
        if (birim !== undefined) {
            updateFields.push(`birim = $${paramIndex++}`);
            updateValues.push(birim);
        }
        if (seri_numarasi !== undefined) {
            updateFields.push(`seri_numarasi = $${paramIndex++}`);
            updateValues.push(seri_numarasi); // null da olabilir
        }
        if (kalem_ozel_notlari !== undefined) {
            updateFields.push(`kalem_ozel_notlari = $${paramIndex++}`);
            updateValues.push(kalem_ozel_notlari); // null da olabilir
        }
        
        // updated_at alanı için trigger yoksa manuel ekle
        // Eğer updated_at için trigger'ınız varsa bu satıra gerek yok, veritabanı otomatik halleder.
        // updateFields.push(`updated_at = CURRENT_TIMESTAMP`); 
        // Bu satırı eklerseniz, paramIndex'i ve updateValues.push() kısmını ona göre ayarlamanız gerekir.
        // VEYA trigger'ınız varsa bu alanı HİÇ GÜNCELLEMEYİN, trigger yapsın.
        // Şimdilik trigger'ın var olduğunu varsayarak updated_at'ı sorguya eklemiyorum.

        if (updateFields.length === 0) { // Hiç güncellenecek alan gelmediyse
            await client.query('ROLLBACK');
            const error = new Error('Güncellenecek bir bilgi gönderilmedi.');
            error.status = 400;
            return next(error);
        }
        
        // WHERE koşulu için parametreleri ekle
        updateValues.push(parseInt(kalemId)); // $${paramIndex++}
        updateValues.push(parseInt(siparisId)); // $${paramIndex++} (Bu aslında WHERE'de kullanılacak, SET'te değil)

        const updateQuery = `
            UPDATE sevkiyat_siparisi_kalemleri 
            SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP 
            WHERE id = $${paramIndex} AND sevkiyat_siparisi_id = $${paramIndex + 1}
            RETURNING *;
        `;
        // NOT: updateValues'a son iki parametreyi (kalemId, siparisId) eklediğimizden emin olmalıyız.
        // paramIndex SET kısmındaki son parametre numarasını tutuyor.
        // Dolayısıyla WHERE için $${paramIndex} ve $${paramIndex + 1} kullanılacak.

        const kalemUpdateResult = await client.query(updateQuery, updateValues);
        const guncellenmisKalem = kalemUpdateResult.rows[0];
        
        // 4. Ana siparişin updated_at alanını güncelle (opsiyonel, eğer trigger yoksa)
        // await client.query('UPDATE sevkiyat_siparisleri SET updated_at = CURRENT_TIMESTAMP WHERE id = $1', [parseInt(siparisId)]);

        // 5. Audit Log
        await logAudit(user_id, username, 'UPDATE_SEVKIYAT_KALEMI', 'sevkiyat_siparisi_kalemleri', guncellenmisKalem.id, eskiKalem, guncellenmisKalem);

        await client.query('COMMIT');
        res.json({
            message: 'Sevkiyat siparişi kalemi başarıyla güncellendi.',
            kalem: guncellenmisKalem
        });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        next(error);
    } finally {
        if (client) {
            client.release();
        }
    }
});



// app.js dosyanızda, diğer kalem API rotalarından sonra veya uygun bir yere:

// Belirli Bir Sevkiyat Siparişi Kalemini Silme
app.delete('/api/sevkiyat-siparisleri/:siparisId/kalemler/:kalemId', authenticateToken,checkPermission('sevkiyat_siparisi_duzenle'), async (req, res, next) => {
    const { siparisId, kalemId } = req.params;
    const user_id = req.user.id; // İşlemi yapan kullanıcı (audit log için)
    const username = req.user.username; // İşlemi yapan kullanıcı (audit log için)

    // ID'lerin geçerliliğini kontrol et
    if (isNaN(parseInt(siparisId)) || isNaN(parseInt(kalemId))) {
        const error = new Error('Geçersiz sipariş ID veya kalem ID formatı.');
        error.status = 400;
        return next(error);
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        // 1. Ana siparişin varlığını ve durumunu kontrol et
        const siparisCheckQuery = 'SELECT durum FROM sevkiyat_siparisleri WHERE id = $1 FOR UPDATE';
        const siparisCheckResult = await client.query(siparisCheckQuery, [parseInt(siparisId)]);

        if (siparisCheckResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Ana sevkiyat siparişi bulunamadı.');
            error.status = 404;
            return next(error);
        }
        const anaSiparisDurumu = siparisCheckResult.rows[0].durum;
        if (anaSiparisDurumu !== 'Hazırlanıyor' && anaSiparisDurumu !== 'Düzeltiliyor') {
            await client.query('ROLLBACK');
            const error = new Error(`Siparişin durumu (${anaSiparisDurumu}) kalem silmeye uygun değil.`);
            error.status = 403; // Forbidden
            return next(error);
        }

        // 2. Silinecek kalemin varlığını ve doğru siparişe ait olduğunu kontrol et, eski değerleri al (audit için)
        const kalemCheckQuery = 'SELECT * FROM sevkiyat_siparisi_kalemleri WHERE id = $1 AND sevkiyat_siparisi_id = $2';
        const kalemCheckResult = await client.query(kalemCheckQuery, [parseInt(kalemId), parseInt(siparisId)]);

        if (kalemCheckResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Silinecek ürün kalemi bulunamadı veya belirtilen siparişe ait değil.');
            error.status = 404;
            return next(error);
        }
        const silinenKalem = kalemCheckResult.rows[0]; // Audit log için sakla

        // 3. Kalemi sil
        const deleteQuery = 'DELETE FROM sevkiyat_siparisi_kalemleri WHERE id = $1 AND sevkiyat_siparisi_id = $2 RETURNING id';
        const deleteResult = await client.query(deleteQuery, [parseInt(kalemId), parseInt(siparisId)]);

        if (deleteResult.rowCount === 0) { // Nadir bir durum, yukarıdaki kontrolle yakalanmalı ama ek bir güvence
            await client.query('ROLLBACK');
            const error = new Error('Kalem silinemedi (beklenmedik bir durum).');
            error.status = 500;
            return next(error);
        }
        
        // 4. Ana siparişin updated_at alanını güncelle (opsiyonel, eğer trigger yoksa)
        // await client.query('UPDATE sevkiyat_siparisleri SET updated_at = CURRENT_TIMESTAMP WHERE id = $1', [parseInt(siparisId)]);

        // 5. Audit Log
        await logAudit(user_id, username, 'DELETE_SEVKIYAT_KALEMI', 'sevkiyat_siparisi_kalemleri', silinenKalem.id, silinenKalem, null);

        await client.query('COMMIT');
        res.status(200).json({ // veya res.status(204).send();
            message: 'Sevkiyat siparişi kalemi başarıyla silindi.',
            silinenKalemId: silinenKalem.id 
        });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        next(error);
    } finally {
        if (client) {
            client.release();
        }
    }
});



// app.js dosyanızda, diğer sevkiyat siparişi rotalarından sonra:

// Bir Sevkiyat Siparişini "Sevket ve Tamamla"
app.post('/api/sevkiyat-siparisleri/:siparisId/tamamla-ve-sevket', authenticateToken,checkPermission('sevkiyat_siparisi_sevket'),  /* GerekirseRolKontrolu, */ async (req, res, next) => {
    const { siparisId } = req.params;
    const user_id = req.user.id; // İşlemi yapan kullanıcı
    const username = req.user.username;

    if (isNaN(parseInt(siparisId))) {
        const error = new Error('Geçersiz sipariş ID formatı.');
        error.status = 400;
        return next(error);
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Transaction Başlat

        // 1. Ana siparişin varlığını ve durumunu kontrol et (FOR UPDATE ile kilitle)
        const siparisQuery = 'SELECT id, durum, siparis_no, kabin_kodu, referans_bina FROM sevkiyat_siparisleri WHERE id = $1 FOR UPDATE';
        const siparisResult = await client.query(siparisQuery, [parseInt(siparisId)]);

        if (siparisResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Sevkiyat siparişi bulunamadı.');
            error.status = 404;
            return next(error);
        }

        const siparis = siparisResult.rows[0];
        if (siparis.durum !== 'Hazırlanıyor' && siparis.durum !== 'Düzeltiliyor') {
            await client.query('ROLLBACK');
            const error = new Error(`Siparişin durumu (${siparis.durum}) sevkiyata uygun değil. Sadece 'Hazırlanıyor' veya 'Düzeltiliyor' durumundaki siparişler sevk edilebilir.`);
            error.status = 403; // Forbidden
            return next(error);
        }

        // 2. Siparişe ait ürün kalemlerini çek
        const kalemlerQuery = 'SELECT sk.id AS kalem_id, sk.urun_id, sk.miktar, sk.seri_numarasi, p.name AS urun_adi, p.stock AS mevcut_stok FROM sevkiyat_siparisi_kalemleri sk JOIN products p ON sk.urun_id = p.id WHERE sk.sevkiyat_siparisi_id = $1';
        const kalemlerResult = await client.query(kalemlerQuery, [siparis.id]);
        const kalemler = kalemlerResult.rows;

        if (kalemler.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Bu sevkiyat siparişinde sevk edilecek ürün kalemi bulunmuyor.');
            error.status = 400; // Bad Request
            return next(error);
        }

        // 3. Her bir kalem için stok kontrolü yap ve stok hareketlerini oluştur
        for (const kalem of kalemler) {
            const istenenMiktar = parseFloat(kalem.miktar);
            const mevcutStok = parseFloat(kalem.mevcut_stok);

            if (mevcutStok < istenenMiktar) {
                await client.query('ROLLBACK');
                const error = new Error(`Yetersiz stok: "${kalem.urun_adi}" (Ürün ID: ${kalem.urun_id}). İstenen: ${istenenMiktar}, Mevcut: ${mevcutStok}.`);
                error.status = 409; // Conflict (veya 400 Bad Request)
                return next(error);
            }

            // Stoktan düş
            const yeniStok = mevcutStok - istenenMiktar;
            await client.query('UPDATE products SET stock = $1 WHERE id = $2', [yeniStok, kalem.urun_id]);

            // Transaction kaydı oluştur
            const transaction_code = await generateTransactionCode('SEV'); // 'SEV' -> Sevkiyat/Çıkış
            const transactionNotes = `Sevkiyat Sipariş No: ${siparis.siparis_no}, Kabin Kodu: ${siparis.kabin_kodu}${siparis.referans_bina ? ', Bina: ' + siparis.referans_bina : ''}${kalem.seri_numarasi ? ', Seri No: ' + kalem.seri_numarasi : ''}, Kalem ID: ${kalem.kalem_id}`;
            
            await client.query(
                `INSERT INTO transactions (product_id, user_id, company_id, quantity, type, transaction_date, notes, product_stock_after_transaction, transaction_code) 
                 VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, $7, $8)`,
                [kalem.urun_id, user_id, siparisResult.rows[0].firma_id, istenenMiktar, 'out', transactionNotes, yeniStok, transaction_code]
            );
             // Not: `siparisResult.rows[0].firma_id` ile ana siparişin firma_id'sini transactions'a ekledim.
        }

        // 4. Ana siparişin durumunu 'Sevk Edildi' ve updated_at alanını güncelle
        const updateSiparisQuery = "UPDATE sevkiyat_siparisleri SET durum = 'Sevk Edildi', updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *";
        const guncellenmisSiparisResult = await client.query(updateSiparisQuery, [siparis.id]);
        
        // 5. Audit Log
        await logAudit(user_id, username, 'SEVKIYAT_TAMAMLANDI', 'sevkiyat_siparisleri', siparis.id, { eski_durum: siparis.durum }, guncellenmisSiparisResult.rows[0]);

        await client.query('COMMIT'); // Her şey yolundaysa transaction'ı onayla

        res.status(200).json({
            message: `Sevkiyat siparişi (No: ${siparis.siparis_no}) başarıyla tamamlandı ve ürünler stoktan düşüldü.`,
            siparis: guncellenmisSiparisResult.rows[0]
        });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        next(error);
    } finally {
        if (client) {
            client.release();
        }
    }
});



// app.js dosyanızda, diğer sevkiyat siparişi rotalarından sonra:

// Bir Sevkiyat Siparişindeki Düzeltmeyi Tamamlama ve Yeniden Sevketme
app.post('/api/sevkiyat-siparisleri/:siparisId/duzeltmeyi-tamamla', authenticateToken, checkPermission('sevkiyat_siparisi_duzeltme_tamamla'),/* YetkiliRolKontrolu, */ async (req, res, next) => {
    const { siparisId } = req.params;
    const user_id = req.user.id; // İşlemi yapan kullanıcı
    const username = req.user.username;

    if (isNaN(parseInt(siparisId))) {
        const error = new Error('Geçersiz sipariş ID formatı.');
        error.status = 400;
        return next(error);
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Transaction Başlat

        // 1. Ana siparişin varlığını ve durumunu kontrol et (FOR UPDATE ile kilitle)
        const siparisQuery = 'SELECT id, durum, siparis_no, kabin_kodu, referans_bina, firma_id FROM sevkiyat_siparisleri WHERE id = $1 FOR UPDATE';
        const siparisResult = await client.query(siparisQuery, [parseInt(siparisId)]);

        if (siparisResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Sevkiyat siparişi bulunamadı.');
            error.status = 404;
            return next(error);
        }

        const siparis = siparisResult.rows[0];
        if (siparis.durum !== 'Düzeltiliyor') { // Sadece 'Düzeltiliyor' durumundaki siparişler için
            await client.query('ROLLBACK');
            const error = new Error(`Siparişin durumu (${siparis.durum}) düzeltmeyi tamamlamaya uygun değil. Sadece 'Düzeltiliyor' durumundaki siparişler yeniden sevk edilebilir.`);
            error.status = 403; // Forbidden
            return next(error);
        }

        // 2. Siparişe ait GÜNCEL ürün kalemlerini çek
        const kalemlerQuery = 'SELECT sk.id AS kalem_id, sk.urun_id, sk.miktar, sk.seri_numarasi, p.name AS urun_adi, p.stock AS mevcut_stok FROM sevkiyat_siparisi_kalemleri sk JOIN products p ON sk.urun_id = p.id WHERE sk.sevkiyat_siparisi_id = $1';
        const kalemlerResult = await client.query(kalemlerQuery, [siparis.id]);
        const kalemler = kalemlerResult.rows;

        if (kalemler.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Bu düzeltilmiş sevkiyat siparişinde sevk edilecek ürün kalemi bulunmuyor.');
            error.status = 400; // Bad Request
            return next(error);
        }

        // 3. Her bir GÜNCEL kalem için stok kontrolü yap ve YENİ stok hareketlerini oluştur
        for (const kalem of kalemler) {
            const istenenMiktar = parseFloat(kalem.miktar);
            const mevcutStok = parseFloat(kalem.mevcut_stok);

            if (mevcutStok < istenenMiktar) {
                await client.query('ROLLBACK');
                const error = new Error(`Yetersiz stok (düzeltme sonrası): "${kalem.urun_adi}" (Ürün ID: ${kalem.urun_id}). İstenen: ${istenenMiktar}, Mevcut: ${mevcutStok}.`);
                error.status = 409; // Conflict
                return next(error);
            }

            // Stoktan düş
            const yeniStok = mevcutStok - istenenMiktar;
            await client.query('UPDATE products SET stock = $1 WHERE id = $2', [yeniStok, kalem.urun_id]);

            // YENİ Transaction kaydı oluştur
            // Düzeltilmiş sevkiyat için 'SEV-DZT' gibi özel bir ön ek kullanabilirsiniz veya yine 'SEV' kullanabilirsiniz.
            const transaction_code = await generateTransactionCode('SEV'); 
            const transactionNotes = `Düzeltilmiş Sevkiyat - Sip.No: ${siparis.siparis_no}, Kabin Kodu: ${siparis.kabin_kodu}${siparis.referans_bina ? ', Bina: ' + siparis.referans_bina : ''}${kalem.seri_numarasi ? ', Seri No: ' + kalem.seri_numarasi : ''}, Kalem ID: ${kalem.kalem_id}`;
            
            await client.query(
                `INSERT INTO transactions (product_id, user_id, company_id, quantity, type, transaction_date, notes, product_stock_after_transaction, transaction_code) 
                 VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, $7, $8)`,
                [kalem.urun_id, user_id, siparis.firma_id, istenenMiktar, 'out', transactionNotes, yeniStok, transaction_code]
            );
        }

        // 4. Ana siparişin durumunu 'Sevk Edildi' (veya 'Düzeltildi ve Sevk Edildi') ve updated_at alanını güncelle
        // İsterseniz farklı bir durum adı da kullanabilirsiniz: 'Düzeltildi ve Sevk Edildi'
        const yeniDurum = 'Sevk Edildi'; 
        const updateSiparisQuery = "UPDATE sevkiyat_siparisleri SET durum = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *";
        const guncellenmisSiparisResult = await client.query(updateSiparisQuery, [yeniDurum, siparis.id]);
        
        // 5. Audit Log
        await logAudit(user_id, username, 'SEVKIYAT_DUZELTME_TAMAMLANDI', 'sevkiyat_siparisleri', siparis.id, { eski_durum: siparis.durum }, guncellenmisSiparisResult.rows[0]);

        await client.query('COMMIT'); // Her şey yolundaysa transaction'ı onayla

        res.status(200).json({
            message: `Sevkiyat siparişi (No: ${siparis.siparis_no}) başarıyla düzeltildi, yeniden sevk edildi ve ürünler stoktan düşüldü.`,
            siparis: guncellenmisSiparisResult.rows[0]
        });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        next(error);
    } finally {
        if (client) {
            client.release();
        }
    }
});




// app.js dosyanızda, diğer sevkiyat siparişi rotalarından sonra:

// Sevk Edilmiş Bir Sevkiyat Siparişini Tamamen İptal Etme
app.post('/api/sevkiyat-siparisleri/:siparisId/tamamen-iptal-et', authenticateToken,checkPermission('sevkiyat_siparisi_tamamen_iptal_et'), async (req, res, next) => {
    const { siparisId } = req.params;
    const user_id = req.user.id; // İşlemi yapan kullanıcı
    const username = req.user.username;

    if (isNaN(parseInt(siparisId))) {
        const error = new Error('Geçersiz sipariş ID formatı.');
        error.status = 400;
        return next(error);
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Transaction Başlat

        // 1. Ana siparişin varlığını ve durumunu kontrol et (FOR UPDATE ile kilitle)
        const siparisQuery = 'SELECT id, durum, siparis_no, kabin_kodu, referans_bina, firma_id FROM sevkiyat_siparisleri WHERE id = $1 FOR UPDATE';
        const siparisResult = await client.query(siparisQuery, [parseInt(siparisId)]);

        if (siparisResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('İptal edilecek sevkiyat siparişi bulunamadı.');
            error.status = 404;
            return next(error);
        }

        const siparis = siparisResult.rows[0];

        if (siparis.durum === 'İptal Edildi') {
            await client.query('ROLLBACK'); // Bir işlem yapmaya gerek yok
            return res.status(200).json({ message: `Sipariş (No: ${siparis.siparis_no}) zaten 'İptal Edildi' durumunda.`, siparis });
        }

        if (siparis.durum !== 'Sevk Edildi' && siparis.durum !== 'Düzeltiliyor') {
            await client.query('ROLLBACK');
            const error = new Error(`Siparişin durumu (${siparis.durum}) tam iptale uygun değil. Sadece 'Sevk Edildi' veya 'Düzeltiliyor' durumundaki siparişler tamamen iptal edilebilir.`);
            error.status = 403; // Forbidden
            return next(error);
        }

        // 2. Eğer sipariş 'Sevk Edildi' durumundaysa stokları iade et
        if (siparis.durum === 'Sevk Edildi') {
            const kalemlerQuery = 'SELECT sk.id AS kalem_id, sk.urun_id, sk.miktar, p.name AS urun_adi FROM sevkiyat_siparisi_kalemleri sk JOIN products p ON sk.urun_id = p.id WHERE sk.sevkiyat_siparisi_id = $1';
            const kalemlerResult = await client.query(kalemlerQuery, [siparis.id]);
            const kalemler = kalemlerResult.rows;

            if (kalemler.length > 0) { // Sadece kalem varsa stok iadesi yap
                for (const kalem of kalemler) {
                    const iadeMiktari = parseFloat(kalem.miktar);

                    // Stoğu geri ekle
                    const productUpdateQuery = 'UPDATE products SET stock = stock + $1 WHERE id = $2 RETURNING stock';
                    const updatedProduct = await client.query(productUpdateQuery, [iadeMiktari, kalem.urun_id]);
                    const yeniStok = updatedProduct.rows[0].stock;

                    // İade/İptal amaçlı transaction kaydı oluştur
                    const iptal_transaction_code = await generateTransactionCode('SIP-IPTAL'); // Yeni bir tip
                    const iptalTransactionNotes = `Tam İptal: Sip.No: ${siparis.siparis_no} için ${kalem.urun_adi} stoğa iade edildi. Kalem ID: ${kalem.kalem_id}.`;
                    
                    await client.query(
                        `INSERT INTO transactions (product_id, user_id, company_id, quantity, type, transaction_date, notes, product_stock_after_transaction, transaction_code) 
                         VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, $7, $8)`,
                        [kalem.urun_id, user_id, siparis.firma_id, iadeMiktari, 'sevkiyat_tam_iptal', iptalTransactionNotes, yeniStok, iptal_transaction_code]
                        // 'sevkiyat_tam_iptal' gibi yeni bir transaction type ENUM'a eklenmeli
                    );
                }
            }
        }
        // Eğer durum 'Düzeltiliyor' ise, stoklar zaten 'duzeltme-baslat' adımında iade edilmişti, tekrar iadeye gerek yok.

        // 3. Ana siparişin durumunu 'İptal Edildi' ve updated_at alanını güncelle
        const yeniDurum = 'İptal Edildi';
        const updateSiparisQuery = "UPDATE sevkiyat_siparisleri SET durum = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *";
        const guncellenmisSiparisResult = await client.query(updateSiparisQuery, [yeniDurum, siparis.id]);
        
        // 4. Audit Log
        await logAudit(user_id, username, 'SEVKIYAT_TAMAMEN_IPTAL_EDILDI', 'sevkiyat_siparisleri', siparis.id, { eski_durum: siparis.durum }, guncellenmisSiparisResult.rows[0]);

        await client.query('COMMIT'); // Her şey yolundaysa transaction'ı onayla

        res.status(200).json({
            message: `Sevkiyat siparişi (No: ${siparis.siparis_no}) başarıyla tamamen iptal edildi. Varsa ilgili ürünler stoğa iade edildi.`,
            siparis: guncellenmisSiparisResult.rows[0]
        });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        next(error);
    } finally {
        if (client) {
            client.release();
        }
    }
});


// app.js dosyanızda, diğer sevkiyat siparişi rotalarından sonra:

// Sevk Edilmiş Bir Sipariş İçin Düzeltme İşlemini Başlatma
app.post('/api/sevkiyat-siparisleri/:siparisId/duzeltme-baslat', authenticateToken, checkPermission('sevkiyat_siparisi_duzeltme_baslat'), async (req, res, next) => {
    const { siparisId } = req.params;
    const user_id = req.user.id; // İşlemi yapan kullanıcı
    const username = req.user.username;

    if (isNaN(parseInt(siparisId))) {
        const error = new Error('Geçersiz sipariş ID formatı.');
        error.status = 400;
        return next(error);
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Transaction Başlat

        // 1. Ana siparişin varlığını ve durumunu kontrol et (FOR UPDATE ile kilitle)
        const siparisQuery = 'SELECT id, durum, siparis_no FROM sevkiyat_siparisleri WHERE id = $1 FOR UPDATE';
        const siparisResult = await client.query(siparisQuery, [parseInt(siparisId)]);

        if (siparisResult.rows.length === 0) {
            await client.query('ROLLBACK');
            const error = new Error('Sevkiyat siparişi bulunamadı.');
            error.status = 404;
            return next(error);
        }

        const siparis = siparisResult.rows[0];
        if (siparis.durum !== 'Sevk Edildi') { // Sadece 'Sevk Edildi' durumundaki siparişler düzeltilebilir
            await client.query('ROLLBACK');
            const error = new Error(`Siparişin durumu (${siparis.durum}) düzeltme başlatmaya uygun değil. Sadece 'Sevk Edildi' durumundaki siparişler için düzeltme başlatılabilir.`);
            error.status = 403; // Forbidden
            return next(error);
        }

        // 2. Bu siparişe ait ve 'tamamla-ve-sevket' sırasında oluşturulmuş 'out' transaction'larını bul.
        // Bu transaction'ların bir şekilde ana siparişe bağlanmış olması gerekir.
        // Örnek olarak, transaction.notes alanında "Sevkiyat Sipariş No: [siparis.siparis_no]" gibi bir referans arayabiliriz.
        // VEYA daha iyisi, 'tamamla-ve-sevket' sırasında transaction'lara sevkiyat_siparisi_kalemleri.id gibi bir referans eklediysek onu kullanabiliriz.
        // Şimdilik notes alanında siparis_no ile arama yaptığımızı varsayalım (bu kısım sizin 'tamamla-ve-sevket'teki not formatınıza göre güncellenmeli):
        
        const orjinalCikisTransactionlariQuery = `
            SELECT id AS transaction_id, product_id, quantity, product_stock_after_transaction 
            FROM transactions 
            WHERE type = 'out' AND notes LIKE $1 
            ORDER BY id DESC; -- En son yapılanları (muhtemelen bu siparişe ait olanları) almak için bir mantık
        `;
        // $1 için notes LIKE '%Sevkiyat Sipariş No: SPSV-XXXX%' gibi bir pattern lazım olacak.
        // Bu kısım önemli ve sizin 'tamamla-ve-sevket' adımında transactions.notes alanına ne yazdığınıza bağlı.
        // Daha sağlam bir yöntem, sevkiyat_siparisi_kalemleri.id'yi transactions tablosuna bir foreign key olarak eklemek
        // veya en azından bir referans sütununa yazmaktır.
        // Şimdilik bu adımı konsept olarak geçiyorum, çünkü bu sorgu sizin veri yapınıza özel olacaktır.
        // Farz edelim ki bu siparişe ait kalemlerin ID'lerini biliyoruz ve onlar üzerinden gidiyoruz.

        const kalemlerQuery = 'SELECT sk.id AS kalem_id, sk.urun_id, sk.miktar, p.name AS urun_adi FROM sevkiyat_siparisi_kalemleri sk JOIN products p ON sk.urun_id = p.id WHERE sk.sevkiyat_siparisi_id = $1';
        const kalemlerResult = await client.query(kalemlerQuery, [siparis.id]);
        const kalemler = kalemlerResult.rows;

        if (kalemler.length === 0) {
            // Bu durum normalde 'Sevk Edildi' bir siparişte olmamalı ama bir kontrol.
            await client.query('ROLLBACK');
            const error = new Error('Düzeltilecek siparişte ürün kalemi bulunamadı. Bu beklenmedik bir durum.');
            error.status = 500;
            return next(error);
        }
        
        // 3. Her bir orijinal çıkış kalemi için stokları iade et ve iade transaction'ı oluştur
        for (const kalem of kalemler) {
            const iadeMiktari = parseFloat(kalem.miktar);

            // Stoğu geri ekle
            const productUpdateQuery = 'UPDATE products SET stock = stock + $1 WHERE id = $2 RETURNING stock';
            const updatedProduct = await client.query(productUpdateQuery, [iadeMiktari, kalem.urun_id]);
            const yeniStok = updatedProduct.rows[0].stock;

            // İade/Düzeltme amaçlı transaction kaydı oluştur
            const iade_transaction_code = await generateTransactionCode('IADE'); // 'IADE' veya 'SEVIPTL' gibi yeni bir tip
            const iadeTransactionNotes = `Düzeltme başlangıcı: Sip.No: ${siparis.siparis_no} için ${kalem.urun_adi} iadesi. Orijinal Kalem ID: ${kalem.kalem_id}.`;
            
            await client.query(
                `INSERT INTO transactions (product_id, user_id, company_id, quantity, type, transaction_date, notes, product_stock_after_transaction, transaction_code) 
                 VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, $6, $7, $8)`,
                [kalem.urun_id, user_id, siparisResult.rows[0].firma_id, iadeMiktari, 'sevkiyat_iade', iadeTransactionNotes, yeniStok, iade_transaction_code]
                // 'sevkiyat_iade' gibi yeni bir transaction type tanımlayabilirsiniz. Ya da type='in', notes'ta belirtilir.
            );
        }

        // 4. Ana siparişin durumunu 'Düzeltiliyor' ve updated_at alanını güncelle
        const updateSiparisQuery = "UPDATE sevkiyat_siparisleri SET durum = 'Düzeltiliyor', updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *";
        const guncellenmisSiparisResult = await client.query(updateSiparisQuery, [siparis.id]);
        
        // 5. Audit Log
        await logAudit(user_id, username, 'SEVKIYAT_DUZELTME_BASLATILDI', 'sevkiyat_siparisleri', siparis.id, { eski_durum: siparis.durum }, guncellenmisSiparisResult.rows[0]);

        await client.query('COMMIT'); // Her şey yolundaysa transaction'ı onayla

        res.status(200).json({
            message: `Sevkiyat siparişi (No: ${siparis.siparis_no}) için düzeltme işlemi başlatıldı. Ürünler stoğa iade edildi ve sipariş düzenlenebilir durumda.`,
            siparis: guncellenmisSiparisResult.rows[0]
        });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        next(error);
    } finally {
        if (client) {
            client.release();
        }
    }
});


// app.js dosyanızda, mevcut GET /api/sevkiyat-siparisleri (listeleme) rotasından sonra:

// Tek Bir Sevkiyat Siparişinin Detaylarını Getirme
app.get('/api/sevkiyat-siparisleri/:id', authenticateToken, checkPermission('sevkiyat_siparisi_goruntule'), async (req, res, next) => {
    const { id } = req.params; // URL'den siparişin ID'sini al

    // ID'nin geçerli bir sayı olup olmadığını kontrol et
    if (isNaN(parseInt(id))) {
        const error = new Error('Geçersiz sipariş ID formatı.');
        error.status = 400; // Bad Request
        return next(error);
    }

    try {
        const query = `
            SELECT 
                ss.id, 
                ss.siparis_no, 
                ss.kabin_kodu, 
                c.id AS firma_id,       -- Firma ID'sini de alalım
                c.name AS firma_adi, 
                u.id AS user_id,        -- Kullanıcı ID'sini de alalım
                u.username AS olusturan_kullanici,
                ss.siparis_tarihi, 
                ss.referans_bina, 
                ss.durum, 
                ss.genel_notlar,
                ss.created_at,
                ss.updated_at
            FROM sevkiyat_siparisleri ss
            LEFT JOIN companies c ON ss.firma_id = c.id
            LEFT JOIN users u ON ss.user_id = u.id
            WHERE ss.id = $1;
        `;
        const result = await pool.query(query, [parseInt(id)]);

        if (result.rows.length === 0) {
            const error = new Error('Sevkiyat siparişi bulunamadı.');
            error.status = 404; // Not Found
            return next(error);
        }

        // Sipariş bulundu, detayları dön
        res.json({ siparis: result.rows[0] });

    } catch (error) {
        next(error);
    }
});


// Kategori Güncelle (Sadece Admin)
app.put('/api/categories/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    const { name, description } = req.body;
    if (!name || name.length < 2) {
        const error = new Error('Kategori adı en az 2 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    try {
        const oldCategoryResult = await pool.query('SELECT name, description FROM categories WHERE id = $1', [id]);
        if (oldCategoryResult.rows.length === 0) {
            const error = new Error('Kategori bulunamadı.');
            error.status = 404;
            return next(error);
        }
        const oldCategory = oldCategoryResult.rows[0];

        const existingCategory = await pool.query('SELECT id FROM categories WHERE name ILIKE $1 AND id != $2', [name, id]);
        if (existingCategory.rows.length > 0) {
            const error = new Error('Bu isimde başka bir kategori zaten mevcut.');
            error.status = 409; // Conflict
            return next(error);
        }

        const result = await pool.query(
            'UPDATE categories SET name = $1, description = $2 WHERE id = $3 RETURNING *',
            [name, description || null, id]
        );
        await logAudit(req.user.id, req.user.username, 'UPDATE', 'categories', id, oldCategory, result.rows[0]);
        res.json({ message: 'Kategori başarıyla güncellendi.', category: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

// Kategori Sil (Sadece Admin) - Bağlı ürünleri kategorisiz yapar
app.delete('/api/categories/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const oldCategoryResult = await pool.query('SELECT name FROM categories WHERE id = $1 FOR UPDATE', [id]);
            if (oldCategoryResult.rows.length === 0) {
                const error = new Error('Kategori bulunamadı.');
                error.status = 404;
                return next(error);
            }
            const oldCategory = oldCategoryResult.rows[0];

            // Bu kategoriye bağlı ürünleri "Kategorisiz" (NULL) olarak güncelle
            await client.query('UPDATE products SET category_id = NULL WHERE category_id = $1', [id]);

            const result = await client.query('DELETE FROM categories WHERE id = $1 RETURNING id, name', [id]);
            await logAudit(req.user.id, req.user.username, 'DELETE', 'categories', id, oldCategory, null);

            await client.query('COMMIT');
            res.json({ message: 'Kategori başarıyla silindi ve bağlı ürünler kategorisiz olarak güncellendi.', category: result.rows[0] });
        } catch (err) {
            await client.query('ROLLBACK');
            next(err);
        } finally {
            client.release();
        }
    } catch (err) {
        next(err);
    }
});


// POST /api/transactions endpoint'ini ekle:
app.post('/api/transactions', authenticateToken, isUserOrAdmin, async (req, res, next) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Frontend'den gelen verileri al
        const { type, productId: rawProductId, quantity: rawQuantity, companyId: rawCompanyId, notes, new_stock_quantity: rawNewStockQuantity } = req.body;
        const userId = req.user.id;
        const username = req.user.username;

        console.log(`🚀 API /api/transactions çağrıldı. Tip: ${type}, ÜrünID: ${rawProductId}, Miktar: ${rawQuantity}`);

        // Temel Validasyonlar
        const finalProductId = parseInt(rawProductId);
        const parsedQuantity = parseFloat(rawQuantity);
        const newStockQuantityForAdjustment = (type === 'adjustment') ? parseFloat(rawNewStockQuantity) : null;

        if (isNaN(finalProductId) || finalProductId <= 0) {
            throw Object.assign(new Error('Geçersiz ürün IDsi.'), { status: 400 });
        }
        if (type !== 'adjustment' && (isNaN(parsedQuantity) || parsedQuantity <= 0)) {
            throw Object.assign(new Error('Miktar sıfırdan büyük bir sayı olmalıdır.'), { status: 400 });
        }
        if (type === 'adjustment' && (newStockQuantityForAdjustment === null || isNaN(newStockQuantityForAdjustment) || newStockQuantityForAdjustment < 0)) {
            throw Object.assign(new Error('Yeni stok miktarı sıfırdan küçük olamaz ve sayı olmalıdır.'), { status: 400 });
        }
        if (type === 'adjustment' && (!notes || notes.trim().length < 5)) {
            throw Object.assign(new Error('Düzeltme işlemi için en az 5 karakter not girmek zorunludur.'), { status: 400 });
        }

        let finalCompanyId = rawCompanyId;
        if (finalCompanyId === 'null' || finalCompanyId === '' || finalCompanyId === undefined || !finalCompanyId) {
            finalCompanyId = null;
        } else {
            const parsedCompanyId = parseInt(finalCompanyId);
            if (isNaN(parsedCompanyId)) {
                throw Object.assign(new Error('Geçersiz firma IDsi.'), { status: 400 });
            }
            finalCompanyId = parsedCompanyId;
        }

        if (type === 'production_in') {
            finalCompanyId = null;
        } else if ((type === 'purchase_in' || type === 'in' || type === 'out') && !finalCompanyId) {
            throw Object.assign(new Error(`${type === 'out' ? 'Çıkış' : 'Giriş'} işlemi için firma seçimi zorunludur.`), { status: 400 });
        }

        // Ürünü Veritabanından Çek
        const productQuery = await client.query('SELECT id, name, stock, product_type FROM products WHERE id = $1 AND is_active = TRUE FOR UPDATE', [finalProductId]);
        if (productQuery.rows.length === 0) {
            throw Object.assign(new Error(`Ürün (ID: ${finalProductId}) bulunamadı veya aktif değil.`), { status: 404 });
        }
        const currentProduct = productQuery.rows[0];
        const oldStock = parseFloat(currentProduct.stock);
        let calculatedNewStock;
        let transactionQuantityForLog = parsedQuantity;

        // Yeni Stok Miktarını Hesapla
        if (type === 'purchase_in' || type === 'production_in' || type === 'in') {
            calculatedNewStock = oldStock + parsedQuantity;
        } else if (type === 'out') {
            if (oldStock < parsedQuantity) {
                throw Object.assign(new Error(`Yetersiz stok! Ürün: ${currentProduct.name}, Mevcut: ${oldStock}, İstenen: ${parsedQuantity}`), { status: 400 });
            }
            calculatedNewStock = oldStock - parsedQuantity;
        } else if (type === 'adjustment') {
            calculatedNewStock = newStockQuantityForAdjustment;
            transactionQuantityForLog = calculatedNewStock - oldStock;
        } else {
            throw Object.assign(new Error(`Bilinmeyen işlem tipi: ${type}`), { status: 400 });
        }

        // Ana Ürünün Stoğunu Güncelle
        await client.query('UPDATE products SET stock = $1 WHERE id = $2', [calculatedNewStock, finalProductId]);

        // İşlem Kodu Oluştur
        const transactionCode = await generateTransactionCode(type);

        // Ana İşlem Kaydını Oluştur
        const mainTransactionQuery = `
            INSERT INTO transactions (product_id, company_id, user_id, type, quantity, product_stock_after_transaction, notes, transaction_code)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *;
        `;
        const mainTransactionResult = await client.query(mainTransactionQuery, [
            finalProductId,
            finalCompanyId,
            userId,
            type,
            transactionQuantityForLog,
            calculatedNewStock,
            notes ? notes.trim() : null,
            transactionCode
        ]);
        const mainTransactionId = mainTransactionResult.rows[0].id;

        // BOM Sonucunu Hazırla
        let bomProcessResult = { applied: false, deductions: [], total_materials_consumed: 0, preview: [] };

        // 'production_in' ise BOM Uygula
        if (type === 'production_in' && parsedQuantity > 0) {
            if (currentProduct.product_type !== 'BITMIS_URUN' && currentProduct.product_type !== 'YARI_MAMUL') {
                console.log(`ℹ️ Product ${finalProductId} (${currentProduct.name}) is not a 'BITMIS_URUN' or 'YARI_MAMUL'. BOM not applicable.`);
            } else {
                console.log(`🏭 Production transaction detected for ${currentProduct.name} (ID: ${finalProductId}) - Applying Full Recursive BOM logic`);
                const requirements = await calculateRecursiveBOM(finalProductId, parsedQuantity, client);

                if (requirements && requirements.length > 0) {
                    const validation = validateStockRequirements(requirements);
                    bomProcessResult.preview = validation.preview;

                    if (!validation.isValid) {
                        const bomValidationError = new Error(`Yetersiz hammadde stoğu:\n${validation.errors.join('\n')}`);
                        bomValidationError.status = 400;
                        bomValidationError.details = validation.preview;
                        throw bomValidationError;
                    }

                    const deductions = await applyBomStockDeductions(requirements, client, userId, username, mainTransactionId);
                    bomProcessResult.applied = true;
                    bomProcessResult.deductions = deductions;
                    bomProcessResult.total_materials_consumed = deductions.length;
                    console.log(`✅ BOM applied successfully: ${bomProcessResult.total_materials_consumed} distinct raw materials consumed`);
                } else {
                    console.log(`ℹ️ No BOM found for product ${finalProductId} - proceeding without BOM.`);
                }
            }
        }

        // Audit Log
        await logAudit(
            userId,
            username,
            type.toUpperCase(),
            'transactions',
            mainTransactionId,
            { old_stock: oldStock, product_id: finalProductId },
            {
                new_stock: calculatedNewStock,
                transaction: mainTransactionResult.rows[0],
                bom_applied: bomProcessResult.applied
            }
        );

        // İşlemi Onayla
        await client.query('COMMIT');

        // Başarı Yanıtı
        let successMessage = 'Stok işlemi başarıyla kaydedildi.';
        if (bomProcessResult.applied && bomProcessResult.total_materials_consumed > 0) {
            successMessage += ` (${bomProcessResult.total_materials_consumed} çeşit hammadde otomatik tüketildi)`;
        }

        res.status(201).json({
            message: successMessage,
            transaction: mainTransactionResult.rows[0],
            bom_result: bomProcessResult.applied ? {
                materials_consumed_count: bomProcessResult.total_materials_consumed,
                deductions_summary: bomProcessResult.deductions.map(d => `${d.product_name}: -${d.deducted} ${d.unit_of_measure}`)
            } : null
        });

    } catch (error) {
    if (client) await client.query('ROLLBACK');

    console.error(
        `❌ API Transaction Error (Type: ${req.body.type || 'Tanımsız'}): `, 
        error.message, 
        error.error_code ? `| Mevcut Hata Kodu: ${error.error_code}` : '',
        error.details ? `| Detaylar: ${JSON.stringify(error.details)}` : '',
        error.stack
    );

    // Varsayılan status
    if (!error.status) {
        error.status = 500;
    }

    // Eğer error_code YOK ise, message'a bakarak ata
    if (!error.error_code) {
        if (error.message.includes('Yetersiz hammadde stoğu')) {
            error.error_code = 'INSUFFICIENT_STOCK';
            error.status = 400;
            // error.details zaten mevcut olabilir, dokunma
        } else if (error.message.includes('Circular BOM reference')) {
            error.message = 'Reçetede döngüsel referans algılandı. Lütfen BOM yapılandırmasını kontrol edin.';
            error.error_code = 'CIRCULAR_BOM_REFERENCE';
            error.status = 400;
        } else if (error.message.includes('Yetersiz stok') && !error.message.includes('hammadde')) {
            error.error_code = 'INSUFFICIENT_PRODUCT_STOCK';
            error.status = 400;
        } else if (error.message.includes('Ürün') && error.message.includes('bulunamadı')) {
            error.error_code = 'PRODUCT_NOT_FOUND';
            error.status = 404;
        } else if (error.message.includes('Firma') && error.message.includes('zorunlu')) {
            error.error_code = 'COMPANY_REQUIRED';
            error.status = 400;
        } else if (error.message.includes('Geçersiz')) {
            error.error_code = 'VALIDATION_ERROR';
            error.status = 400;
        }
    }

    next(error);

} finally {
    if (client) {
        client.release();
    }
}
});

// ------------------- FİRMA YÖNETİMİ API'leri -------------------

// Firma Ekle (Sadece Admin)
app.post('/api/companies', authenticateToken, isAdmin, async (req, res, next) => {
    const { name, contact_person, phone, address, tax_office, tax_number, type } = req.body;

    // Validasyon
    if (!name || name.length < 3) {
        const error = new Error('Firma adı en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    const validTypes = ['customer', 'supplier', 'both'];
    if (!type || !validTypes.includes(type)) {
        const error = new Error('Geçersiz firma tipi. Geçerli tipler: customer, supplier, both.');
        error.status = 400;
        return next(error);
    }

    try {
        const existingCompany = await pool.query('SELECT id FROM companies WHERE name ILIKE $1', [name]);
        if (existingCompany.rows.length > 0) {
            const error = new Error('Bu isimde bir firma zaten mevcut.');
            error.status = 409; // Conflict
            return next(error);
        }

        const result = await pool.query(
            'INSERT INTO companies (name, contact_person, phone, address, tax_office, tax_number, type) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [name, contact_person || null, phone || null, address || null, tax_office || null, tax_number || null, type]
        );
        await logAudit(req.user.id, req.user.username, 'CREATE', 'companies', result.rows[0].id, null, result.rows[0]);
        res.status(201).json({ message: 'Firma başarıyla eklendi.', company: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

// Tüm Firmaları Getir (Filtreleme, Sayfalama, Sıralama)
app.get('/api/companies', authenticateToken, async (req, res, next) => {
    try {
        let { page = 1, limit = 10, type = 'all', sortBy = 'id', sortOrder = 'asc' } = req.query;

        page = parseInt(page);
        limit = parseInt(limit);
        const offset = (page - 1) * limit;

        if (isNaN(page) || page <= 0 || isNaN(limit) || limit <= 0) {
            const error = new Error('Geçersiz sayfa veya limit değeri.');
            error.status = 400;
            return next(error);
        }

        const validSortColumns = ['id', 'name', 'contact_person', 'phone', 'type'];
        const validSortOrders = ['asc', 'desc'];

        const column = validSortColumns.includes(sortBy) ? sortBy : 'id';
        const order = validSortOrders.includes(sortOrder) ? sortOrder : 'asc';

        let whereClauses = [];
        let queryParams = [];
        let paramIndex = 1;

        if (type && type !== 'all') {
            const validTypes = ['customer', 'supplier', 'both'];
            if (validTypes.includes(type)) {
                whereClauses.push(`type = $${paramIndex}`);
                queryParams.push(type);
                paramIndex++;
            } else {
                const error = new Error('Geçersiz firma tipi filtresi.');
                error.status = 400;
                return next(error);
            }
        }

        const whereCondition = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        let companiesQuery = `SELECT * FROM companies ${whereCondition} ORDER BY ${column} ${order} LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        queryParams.push(limit, offset);

        let countQuery = `SELECT COUNT(*) FROM companies ${whereCondition}`;

        const companiesResult = await pool.query(companiesQuery, queryParams);
        const countResult = await pool.query(countQuery, queryParams.slice(0, queryParams.length - 2)); // Limit ve offset olmadan sayım

        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / limit);

        res.json({
            companies: companiesResult.rows,
            currentPage: page,
            totalPages: totalPages,
            totalItems: totalItems
        });
    } catch (err) {
        next(err);
    }
});



// Firma Güncelle (Sadece Admin)
app.put('/api/companies/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    const { name, contact_person, phone, address, tax_office, tax_number, type } = req.body;

    // Validasyon
    if (!name || name.length < 3) {
        const error = new Error('Firma adı en az 3 karakter olmalıdır.');
        error.status = 400;
        return next(error);
    }
    const validTypes = ['customer', 'supplier', 'both'];
    if (!type || !validTypes.includes(type)) {
        const error = new Error('Geçersiz firma tipi. Geçerli tipler: customer, supplier, both.');
        error.status = 400;
        return next(error);
    }

    try {
        const oldCompanyResult = await pool.query('SELECT * FROM companies WHERE id = $1', [id]);
        if (oldCompanyResult.rows.length === 0) {
            const error = new Error('Firma bulunamadı.');
            error.status = 404;
            return next(error);
        }
        const oldCompany = oldCompanyResult.rows[0];

        const existingCompany = await pool.query('SELECT id FROM companies WHERE name ILIKE $1 AND id != $2', [name, id]);
        if (existingCompany.rows.length > 0) {
            const error = new Error('Bu isimde başka bir firma zaten mevcut.');
            error.status = 409; // Conflict
            return next(error);
        }

        const result = await pool.query(
            'UPDATE companies SET name = $1, contact_person = $2, phone = $3, address = $4, tax_office = $5, tax_number = $6, type = $7 WHERE id = $8 RETURNING *',
            [name, contact_person || null, phone || null, address || null, tax_office || null, tax_number || null, type, id]
        );
        await logAudit(req.user.id, req.user.username, 'UPDATE', 'companies', id, oldCompany, result.rows[0]);
        res.json({ message: 'Firma başarıyla güncellendi.', company: result.rows[0] });
    } catch (err) {
        next(err);
    }
});

// Firma Sil (Sadece Admin) - Bağlı hareket varsa silinmez
app.delete('/api/companies/:id', authenticateToken, isAdmin, async (req, res, next) => {
    const { id } = req.params;
    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const oldCompanyResult = await pool.query('SELECT name FROM companies WHERE id = $1 FOR UPDATE', [id]);
            if (oldCompanyResult.rows.length === 0) {
                const error = new Error('Firma bulunamadı.');
                error.status = 404;
                return next(error);
            }
            const oldCompany = oldCompanyResult.rows[0];

            // Firmaya bağlı stok hareketleri var mı kontrol et
            const transactionCountResult = await client.query('SELECT COUNT(*) FROM transactions WHERE company_id = $1', [id]);
            const transactionCount = parseInt(transactionCountResult.rows[0].count);

            if (transactionCount > 0) {
                await client.query('ROLLBACK');
                const error = new Error('Bu firmaya bağlı stok hareketleri olduğu için silinemez.');
                error.status = 400;
                return next(error);
            }

            const result = await pool.query('DELETE FROM companies WHERE id = $1 RETURNING id, name', [id]);
            await logAudit(req.user.id, req.user.username, 'DELETE', 'companies', id, oldCompany, null);

            await client.query('COMMIT');
            res.json({ message: 'Firma başarıyla silindi.', company: result.rows[0] });
        } catch (err) {
            await client.query('ROLLBACK');
            next(err);
        } finally {
            client.release();
        }
    } catch (err) {
        next(err);
    }
});

// ÖNCE: Firma arama endpoint'i (autocomplete için) - SPESİFİK ROUTE ÖNCE OLMALI
app.get('/api/companies/search', authenticateToken, async (req, res, next) => {
    const { query: searchQuery } = req.query;

    if (!searchQuery || searchQuery.length < 2) { // Minimum 2 karakter arama için
        return res.json([]);
    }

    try {
        const searchPattern = `%${searchQuery.toLowerCase()}%`;
        const { rows } = await pool.query(
            `SELECT id, name, tax_number FROM companies
             WHERE LOWER(name) ILIKE $1 OR LOWER(tax_number) ILIKE $1
             ORDER BY name ASC LIMIT 10`, // İlk 10 sonucu getir
            [searchPattern]
        );
        res.json(rows);
    } catch (error) {
        next(error);
    }
});

// SONRA: Tek Firma Getir - GENEL ROUTE SONRA OLMALI
app.get('/api/companies/:id', authenticateToken, async (req, res, next) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT * FROM companies WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            const error = new Error('Firma bulunamadı.');
            error.status = 404;
            return next(error);
        }
        res.json({ company: result.rows[0] });
    } catch (err) {
        next(err);
    }
});


// ------------------- STOK HAREKETLERİ API'leri -------------------

// Yardımcı fonksiyon: İşlem kodu oluşturma
// app.js dosyasının üstünde import/require olacak:
// const { nanoid } = require('nanoid'); // veya import { nanoid } from 'nanoid';

// ...

async function generateTransactionCode(type) {
    let prefix;
    if (type === 'purchase_in') {
        prefix = 'SAT';
    } else if (type === 'production_in') {
        prefix = 'URE';
    } else if (type === 'out') {
        prefix = 'SEV';
    } else if (type === 'adjustment') {
        prefix = 'DUZ';
    } else if (type === 'bom_out') { // Bunu eklemiştik BOM tüketimleri için
        prefix = 'BMO'; 
    } else if (type === 'in') {
        prefix = 'GIR';
    } else if (type === 'SIPSV') { // <-- YENİ/GÜNCELLENMİŞ KISIM
        prefix = 'SPSV'; 
    } else {
        prefix = 'BLN';
    }

    const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const uniqueIdPart = nanoid(6).toUpperCase();

    return `${prefix}-${today}-${uniqueIdPart}`; // <-- DOĞRU RETURN SATIRI

}


/**
 * Multi-Level Recursive BOM Calculation
 * @param {number} productId - Ana ürün ID
 * @param {number} quantity - Üretilen miktar  
 * @param {object} client - PostgreSQL client (transaction içinde)
 * @param {Set} processedProducts - Circular reference engelleme için
 * @returns {Array} Hammadde listesi [{product_id, total_quantity_required, product_name, unit_of_measure}]
 */
async function calculateRecursiveBOM(productId, quantity, client, processedProducts = new Set(), depth = 0) {
    // Depth limit ekleyin (sonsuz döngüyü engeller)
    if (depth > 10) {
        console.error(`❌ BOM calculation depth limit exceeded for product ${productId}`);
        throw new Error(`BOM hesaplaması çok derin - muhtemelen döngüsel referans var (Product ID: ${productId})`);
    }

    // Circular reference kontrolü
    if (processedProducts.has(productId)) {
        const errorMessage = `Reçetede döngüsel referans algılandı: Ürün ID ${productId} zaten işlenmekte olan bir reçete yolunda tekrar bulundu.`;
        console.error(`❌ ${errorMessage}`);
        
        const error = new Error(errorMessage);
        error.status = 400;
        error.error_code = 'CIRCULAR_BOM_REFERENCE';
        error.details = {
            offending_product_id: productId,
            message: "Döngüsel BOM referansı nedeniyle reçete hesaplaması durduruldu."
        };
        throw error;
    }
    
    processedProducts.add(productId);
    
    // İşlem başlangıcında detaylı log
    console.log(`${'  '.repeat(depth)}🔄 Calculating BOM for product ${productId}, quantity: ${quantity}, depth: ${depth}`);
    
    try {
        // Bu ürünün reçetesini al
        const bomQuery = `
            SELECT 
                bom.raw_material_id,
                bom.quantity_required,
                p.product_type,
                p.name as raw_material_name,
                p.unit_of_measure,
                p.stock as current_stock
            FROM bill_of_materials bom
            JOIN products p ON bom.raw_material_id = p.id
            WHERE bom.finished_product_id = $1 AND p.is_active = TRUE
            ORDER BY p.name
        `;
        
        const bomResult = await client.query(bomQuery, [productId]);
        const bomItems = bomResult.rows;
        
        console.log(`${'  '.repeat(depth)}📋 Found ${bomItems.length} BOM items for product ${productId}`);
        
        if (bomItems.length === 0) {
            console.log(`${'  '.repeat(depth)}ℹ️ No BOM found for product ${productId}`);
            return [];
        }
        
        let totalRequirements = [];
        
        for (const item of bomItems) {
            const requiredQuantity = parseFloat(item.quantity_required) * parseFloat(quantity);
            
            console.log(`${'  '.repeat(depth)}  📋 ${item.raw_material_name} (${item.product_type}): ${requiredQuantity} ${item.unit_of_measure} (Unit required: ${item.quantity_required}, Production qty: ${quantity})`);
            
            // Çok büyük miktar kontrolü
            if (requiredQuantity > 1000000) {
                console.warn(`${'  '.repeat(depth)}⚠️ WARNING: Very large quantity calculated: ${requiredQuantity} for ${item.raw_material_name}`);
                console.warn(`${'  '.repeat(depth)}   Unit required: ${item.quantity_required}, Production quantity: ${quantity}`);
            }
            
            if (item.product_type === 'HAMMADDE') {
                // Hammadde ise direkt ekle
                totalRequirements.push({
                    product_id: item.raw_material_id,
                    total_quantity_required: requiredQuantity,
                    product_name: item.raw_material_name,
                    unit_of_measure: item.unit_of_measure,
                    current_stock: parseFloat(item.current_stock),
                    product_type: 'HAMMADDE'
                });
                
            } else if (item.product_type === 'YARI_MAMUL' || item.product_type === 'BITMIS_URUN') {
                // Yarı mamul/Bitmiş ürün ise önce o ürünü de işle
                totalRequirements.push({
                    product_id: item.raw_material_id,
                    total_quantity_required: requiredQuantity,
                    product_name: item.raw_material_name,
                    unit_of_measure: item.unit_of_measure,
                    current_stock: parseFloat(item.current_stock),
                    product_type: item.product_type
                });
                
                // Sonra recursive olarak o ürünün hammaddelerini de hesapla
                const nestedRequirements = await calculateRecursiveBOM(
                    item.raw_material_id, 
                    requiredQuantity, 
                    client, 
                    new Set(processedProducts), // Copy set to avoid mutation
                    depth + 1 // Depth arttır
                );
                
                // Nested requirements'ları merge et
                totalRequirements = mergeRequirements(totalRequirements, nestedRequirements);
            }
        }
        
        // Final merge: Aynı hammaddeleri birleştir
        const finalMerged = [];
        totalRequirements.forEach(req => {
            const existingIndex = finalMerged.findIndex(existing => existing.product_id === req.product_id);
            
            if (existingIndex >= 0) {
                // Aynı ürün varsa miktarları topla
                const oldQty = finalMerged[existingIndex].total_quantity_required;
                finalMerged[existingIndex].total_quantity_required += req.total_quantity_required;
                console.log(`${'  '.repeat(depth)}🔄 Merged ${req.product_name}: ${oldQty} + ${req.total_quantity_required} = ${finalMerged[existingIndex].total_quantity_required}`);
            } else {
                // Yeni ürün ise ekle
                finalMerged.push({ ...req });
            }
        });

        console.log(`${'  '.repeat(depth)}🔄 Final merge: ${totalRequirements.length} → ${finalMerged.length} requirements`);
        
        // Çok büyük miktarları tekrar kontrol et
        finalMerged.forEach(req => {
            if (req.total_quantity_required > 1000000) {
                console.error(`${'  '.repeat(depth)}❌ VERY LARGE QUANTITY DETECTED: ${req.product_name}: ${req.total_quantity_required} ${req.unit_of_measure}`);
            }
        });
        
        return finalMerged;
        
    } catch (error) {
        console.error(`❌ Error calculating BOM for product ${productId} at depth ${depth}:`, error);
        throw error;
    }
}


/**
 * Requirement listelerini birleştir (aynı ürünler için miktarları topla)
 */
function mergeRequirements(existing, newRequirements) {
    const merged = [...existing];
    
    newRequirements.forEach(newReq => {
        const existingIndex = merged.findIndex(req => req.product_id === newReq.product_id);
        
        if (existingIndex >= 0) {
            // Mevcut ürün varsa miktarları topla
            merged[existingIndex].total_quantity_required += newReq.total_quantity_required;
        } else {
            // Yeni ürün ise ekle
            merged.push(newReq);
        }
    });
    
    return merged;
}

/**
 * Stok yetersizliği kontrolü ve preview
 * @param {Array} requirements - BOM requirements
 * @returns {Object} {isValid: boolean, errors: Array, preview: Array}
 */
function validateStockRequirements(requirements) {
    const errors = [];
    const preview = [];
    let isValid = true;
    
    requirements.forEach(req => {
        const isInsufficient = req.current_stock < req.total_quantity_required;
        
        preview.push({
            product_name: req.product_name,
            required: req.total_quantity_required,
            available: req.current_stock,
            unit: req.unit_of_measure,
            sufficient: !isInsufficient
        });
        
        if (isInsufficient) {
            isValid = false;
            errors.push(
                `${req.product_name}: Gerekli ${req.total_quantity_required} ${req.unit_of_measure}, Mevcut ${req.current_stock} ${req.unit_of_measure}`
            );
        }
    });
    
    return { isValid, errors, preview };
}

// 📝 YAPIŞTIR: (yeni fonksiyon ekle)

async function getDirectComponentsPreview(mainProduct, quantityToProduce, client) {
    console.log(`🔄 Calculating DIRECT components for product ${mainProduct.id} (${mainProduct.name}), quantity: ${quantityToProduce}`);

    const directBomQuery = `
        SELECT
            p.id as component_id,
            p.name as component_name,
            p.product_type as component_type,
            p.stock as component_current_stock,
            p.unit_of_measure as component_unit,
            bom.quantity_required
        FROM bill_of_materials bom
        JOIN products p ON bom.raw_material_id = p.id
        WHERE bom.finished_product_id = $1 AND p.is_active = TRUE
        ORDER BY p.name;
    `;
    const bomResult = await client.query(directBomQuery, [mainProduct.id]);
    const directComponents = bomResult.rows;

    if (directComponents.length === 0) {
    return {
        view_type: 'components',
        has_bom: false, // Reçete kalemi yoksa BOM'u yok gibi kabul edebiliriz.
        product_name: mainProduct.name,
        quantity: quantityToProduce,
        is_valid: true, // Herhangi bir bileşen olmadığı için "geçerli" sayılabilir veya duruma göre false.
                        // Genellikle reçetesi olmayan bir şey için "geçerli" demek mantıklı.
        total_items: 0,
        items: [],
        errors: [{ message: 'Bu ürün için doğrudan reçete kalemi bulunamadı.' }] 
        // Veya errors: [] ve ana bir "message" alanı eklenebilir:
        // message: 'Bu ürün için doğrudan reçete kalemi bulunamadı.'
        // Ancak hataları "errors" dizisinde toplamak daha standart.
    };
}

    let isValidOverall = true;
    const componentPreviewList = [];
    const errors = [];

    for (const component of directComponents) {
        const requiredQuantity = parseFloat(component.quantity_required) * quantityToProduce;
        const availableStock = parseFloat(component.component_current_stock);
        const isSufficient = availableStock >= requiredQuantity;

        if (!isSufficient) {
            isValidOverall = false;
            errors.push(`${component.component_name}: Gerekli ${requiredQuantity} ${component.component_unit}, Mevcut ${availableStock} ${component.component_unit}`);
        }

        componentPreviewList.push({
            product_id: component.component_id,
            product_name: component.component_name,
            product_type: component.component_type,
            required: requiredQuantity,
            available: availableStock,
            unit: component.component_unit,
            sufficient: isSufficient
        });
    }

    return {
    view_type: 'components',
    has_bom: true,
    product_name: mainProduct.name,
    quantity: quantityToProduce,
    is_valid: isValidOverall,                // Standart isim
    total_items: componentPreviewList.length,  // Standart isim
    items: componentPreviewList,               // Standart isim
    errors: errors
    };
}


// 📝 YAPIŞTIR: (yeni fonksiyon ekle)

async function getRecursiveRawMaterialsPreview(mainProduct, quantityToProduce, client) {
    console.log(`🔄 Calculating RECURSIVE raw materials for product ${mainProduct.id} (${mainProduct.name}), quantity: ${quantityToProduce}`);

    // calculateRecursiveBOM, zaten tüm nihai hammaddeleri ve birleştirilmiş miktarları döner
    const requirements = await calculateRecursiveBOM(mainProduct.id, quantityToProduce, client);

    if (!requirements || requirements.length === 0) {
    return {
        view_type: 'raw_materials',
        has_bom: false,
        product_name: mainProduct.name,
        quantity: quantityToProduce,
        is_valid: true, // Teknik olarak bir yetersizlik yok.
        total_items: 0,
        items: [],
        errors: [{ message: 'Bu ürün için reçete bulunamadı veya reçete boş.' }]
    };
}

    // validateStockRequirements, requirements listesindeki her bir öğe için stok kontrolü yapar
    const validation = validateStockRequirements(requirements);

    // const rawMaterialCount = ...; // Bu satıra artık ihtiyacımız yok, silebilirsin.

return {
    view_type: 'raw_materials',
    has_bom: true,
    product_name: mainProduct.name,
    quantity: quantityToProduce,
    is_valid: validation.isValid,
    total_items: validation.preview.length, // Önizlemedeki tüm farklı kalemlerin sayısı
    items: validation.preview,              // Önizleme listesi
    errors: validation.errors
};
}

/**
 * BOM bazlı stok düşümlerini uygula
 */


async function applyBomStockDeductions(requirements, client, userId, username, transactionId) {
    console.log(`📦 Applying BOM stock deductions for ${requirements.length} materials (ALL TYPES)`);
    const deductionLogs = [];
    
    // ❌ ESKİ: const hammaddeRequirements = requirements.filter(req => req.product_type === 'HAMMADDE');
    // ✅ YENİ: Hepsini tüket (HAMMADDE + YARI_MAMUL + BITMIS_URUN)
    const allRequirements = requirements;

    for (let i = 0; i < allRequirements.length; i++) {
        const req = allRequirements[i];
        const oldStock = parseFloat(req.current_stock);
        const requiredQty = parseFloat(req.total_quantity_required);
        const newStock = oldStock - requiredQty;

        await client.query(
            'UPDATE products SET stock = $1 WHERE id = $2',
            [newStock, req.product_id]
        );

        const bomTransactionCode = `${transactionId}-BOM-${req.product_id}-${Date.now()}-${i}`;
        
        await client.query(`
            INSERT INTO transactions 
             (product_id, user_id, type, quantity, product_stock_after_transaction, notes, transaction_code)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            req.product_id,
            userId,
            'out', 
            requiredQty,
            newStock,
            `BOM otomatik tüketimi (${req.product_type}) - Ana işlem: ${transactionId} - Ürün: ${req.product_name}`,
            bomTransactionCode
        ]);

        // Audit log - Ürün tipini dahil et
        await logAudit(
            userId,
            username,
            `BOM_${req.product_type}_CONSUMED`, // Dinamik action type
            'products',
            req.product_id.toString(), 
            { 
                stock: oldStock,
                unit_of_measure: req.unit_of_measure,
                product_type: req.product_type // Tip bilgisi ekle
            },
            { 
                stock: newStock,
                consumed_quantity: requiredQty,
                unit_of_measure: req.unit_of_measure,
                product_type: req.product_type, // Tip bilgisi ekle
                main_production_transaction_id: transactionId,
                bom_side_transaction_code: bomTransactionCode
            }
        );

        deductionLogs.push({
            product_id: req.product_id,
            product_name: req.product_name,
            product_type: req.product_type, // Tip bilgisini ekle
            old_stock: oldStock,
            deducted: requiredQty,
            new_stock: newStock,
            unit_of_measure: req.unit_of_measure
        });

        console.log(`  ✅ ${req.product_name} (${req.product_type}): ${oldStock} → ${newStock} (-${requiredQty} ${req.unit_of_measure})`);
    }

    return deductionLogs;
}




// Stok Uyarıları Rotası (Kritik Stok Seviyesi)
app.get('/api/alerts/low-stock', authenticateToken, async (req, res, next) => {
    try {
        const query = `
            SELECT p.id, p.name, p.barcode, p.stock, p.min_stock_level, c.name AS category_name
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            WHERE p.stock <= p.min_stock_level AND p.min_stock_level > 0 AND p.is_active = TRUE
            ORDER BY p.name ASC;
        `;
        const result = await pool.query(query);
        res.json({ lowStockProducts: result.rows });
    } catch (err) {
        next(err);
    }
});



// BOM Önizleme Endpoint (Frontend production sayfası için)
app.get('/api/bom-preview/:productId/:quantity', authenticateToken, isUretimOrAdmin, async (req, res, next) => {
    const { productId, quantity } = req.params;
    const viewType = req.query.view || 'raw_materials'; // Varsayılan 'raw_materials'

    // Validation
    const parsedProductId = parseInt(productId);
    const parsedQuantity = parseFloat(quantity);

    if (isNaN(parsedProductId) || parsedProductId <= 0) {
        return next(Object.assign(new Error('Geçerli bir ürün ID\'si gereklidir.'), { status: 400 }));
    }
    if (isNaN(parsedQuantity) || parsedQuantity <= 0) {
        return next(Object.assign(new Error('Geçerli bir miktar gereklidir.'), { status: 400 }));
    }

    const client = await pool.connect();
    try {
        const productCheck = await client.query('SELECT id, name, product_type FROM products WHERE id = $1 AND is_active = TRUE', [parsedProductId]);
        if (productCheck.rows.length === 0) {
            return next(Object.assign(new Error('Ürün bulunamadı veya aktif değil.'), { status: 404 }));
        }
        const product = productCheck.rows[0];

        if (product.product_type !== 'BITMIS_URUN' && product.product_type !== 'YARI_MAMUL') {
            return next(Object.assign(new Error('BOM önizlemesi sadece bitmiş ürün ve yarı mamul için kullanılabilir.'), { status: 400 }));
        }

        let responseData = {};

        if (viewType === 'components') {
            // Sadece Doğrudan Bileşenleri Göster
            responseData = await getDirectComponentsPreview(product, parsedQuantity, client);
        } else { // Varsayılan veya viewType === 'raw_materials'
            // Tüm Nihai Hammaddeleri Göster
            responseData = await getRecursiveRawMaterialsPreview(product, parsedQuantity, client);
        }

        res.json(responseData);

    } catch (error) {
        console.error(`❌ BOM Preview Error (Product: ${productId}, View: ${viewType}):`, error.message, error.stack);
        next(error);
    } finally {
        if (client) client.release();
    }
});

// ------------------- RAPORLAMA ENDPOINTLERİ -------------------

// Ana Rapor Verisi Endpoint'i
app.get('/api/reports/transactions', authenticateToken, async (req, res, next) => {
    const {
        startDate,
        endDate,
        type,
        userId,
        companyId,
        productId,
        searchQuery
    } = req.query;
    
    // GEÇICI DEBUG: Gelen parametreleri logla
    console.log('Gelen parametreler:', { startDate, endDate, type, userId, companyId, productId, searchQuery });

    let query = `
        SELECT
            t.id AS transaction_id,
            t.transaction_code,
            t.transaction_date,
            t.type AS transaction_type,
            t.quantity,
            t.notes AS transaction_notes,
            p.name AS product_name,
            p.barcode AS product_barcode,
            p.stock AS product_current_stock,
            p.min_stock_level AS product_min_stock_level,
            c.name AS company_name,
            cat.name AS category_name,
            u.username AS user_username,
            u.full_name AS user_full_name,
            t.product_stock_after_transaction
        FROM
            transactions t
        LEFT JOIN
            products p ON t.product_id = p.id
        LEFT JOIN
            companies c ON t.company_id = c.id
        LEFT JOIN
            users u ON t.user_id = u.id
        LEFT JOIN
            categories cat ON p.category_id = cat.id
        WHERE 1=1
    `;
    const values = [];
    let paramIndex = 1;

    if (startDate && startDate.trim() !== '' && startDate !== 'undefined' && startDate !== 'null') {
    query += ` AND DATE(t.transaction_date) >= $${paramIndex++}`;
    values.push(startDate);
}
if (endDate && endDate.trim() !== '' && endDate !== 'undefined' && endDate !== 'null') {
    query += ` AND DATE(t.transaction_date) <= $${paramIndex++}`;
    values.push(endDate);
}
    if (type && type !== 'Tümü') { // Frontend'den 'Tümü' gelirse filtreleme yapma
        query += ` AND t.type = $${paramIndex++}`;
        values.push(type);
    }
    if (userId && userId !== 'Tümü') {
        query += ` AND t.user_id = $${paramIndex++}`;
        values.push(parseInt(userId));
    }
    if (companyId && companyId !== 'Tümü') {
        if (companyId === 'null') { // Frontend'den gelen 'null' stringi için
            query += ` AND t.company_id IS NULL`;
        } else {
            query += ` AND t.company_id = $${paramIndex++}`;
            values.push(parseInt(companyId));
        }
    }
    if (productId && productId !== 'Tümü') {
        query += ` AND t.product_id = $${paramIndex++}`;
        values.push(parseInt(productId));
    }
    if (searchQuery) {
        const searchPattern = `%${searchQuery.toLowerCase()}%`;
        query += `
            AND (
                LOWER(t.transaction_code) ILIKE $${paramIndex} OR
                LOWER(p.name) ILIKE $${paramIndex} OR
                LOWER(c.name) ILIKE $${paramIndex} OR
                LOWER(p.barcode) ILIKE $${paramIndex} OR
                LOWER(u.username) ILIKE $${paramIndex} OR
                LOWER(t.notes) ILIKE $${paramIndex}
            )`;
        values.push(searchPattern);
        paramIndex++;
    }

    query += ` ORDER BY t.transaction_date DESC;`; // Tarihe göre azalan sıralama

    try {
        const { rows } = await pool.query(query, values);

        // Düzeltme işlemleri için audit log'lardan detayları çekme ve birleştirme
        const formattedRows = await Promise.all(rows.map(async row => {
            let notes = row.transaction_notes;
            // Sadece 'adjustment' tipi işlemler için audit log'u kontrol et
            if (row.transaction_type === 'adjustment') {
                // Audit log'u transaction_id ve product_id ile bulmaya çalış
                // transaction_id'ye ait audit log kaydı yoksa, ürünün stok değişimi logunu ara
                const auditLogRes = await pool.query(
    `SELECT old_value, new_value FROM audit_logs
     WHERE table_name = 'transactions' AND record_id = $1 
     ORDER BY timestamp DESC LIMIT 1`,
    [row.transaction_id]
);

                if (auditLogRes.rows.length > 0) {
                    const auditLog = auditLogRes.rows[0];
                    let changeDetails = [];
                    if (auditLog.old_value && auditLog.new_value) {
                        // Eğer ürün stok değişimi logu ise
                        if (auditLog.old_value.stock !== undefined && auditLog.new_value.stock !== undefined) {
                            changeDetails.push(`Stok: ${auditLog.old_value.stock} -> ${auditLog.new_value.stock}`);
                        }
                        // Eğer işlem logu ise (daha detaylı bilgi içerebilir)
                        if (auditLog.old_value.old_stock !== undefined && auditLog.new_value.new_stock !== undefined) {
                             changeDetails.push(`Stok: ${auditLog.old_value.old_stock} -> ${auditLog.new_value.new_stock}`);
                        }
                    }
                    if (changeDetails.length > 0) {
                        notes = (notes ? notes + ' - ' : '') + `Düzeltme Detayı: (${changeDetails.join(', ')})`;
                    }
                }
            }
            return {
                ...row,
                transaction_notes: notes,
                transaction_date: moment(row.transaction_date).format('DD.MM.YYYY HH:mm:ss')
            };
        }));

        res.json(formattedRows);
    } catch (error) {
        console.error('Rapor verisi çekme hatası:', error);
        next(error);
    }
});

// Raporu PDF olarak dışa aktırma
app.get('/api/reports/transactions/pdf', authenticateToken, async (req, res, next) => {
    const {
        startDate,
        endDate,
        type,
        userId,
        companyId,
        productId,
        searchQuery
    } = req.query;

    // Rapor verisini çekmek için /api/reports/transactions endpoint'indeki sorguyu kullan
    let query = `
        SELECT
            p.unit_of_measure AS product_unit_of_measure,
            t.id AS transaction_id,
            t.transaction_code,
            t.transaction_date,
            t.type AS transaction_type,
            t.quantity,
            t.notes AS transaction_notes,
            p.name AS product_name,
            p.barcode AS product_barcode,
            p.stock AS product_current_stock,
            p.min_stock_level AS product_min_stock_level,
            c.name AS company_name,
            cat.name AS category_name,
            u.username AS user_username,
            u.full_name AS user_full_name,
            t.product_stock_after_transaction
        FROM
            transactions t
        LEFT JOIN
            products p ON t.product_id = p.id
        LEFT JOIN
            companies c ON t.company_id = c.id
        LEFT JOIN
            users u ON t.user_id = u.id
        LEFT JOIN
            categories cat ON p.category_id = cat.id
        WHERE 1=1
    `;
    const values = [];
    let paramIndex = 1;

   if (startDate && startDate.trim() !== '' && startDate !== 'undefined' && startDate !== 'null') {
    query += ` AND DATE(t.transaction_date) >= $${paramIndex++}`;
    values.push(startDate);
}
if (endDate && endDate.trim() !== '' && endDate !== 'undefined' && endDate !== 'null') {
    query += ` AND DATE(t.transaction_date) <= $${paramIndex++}`;
    values.push(endDate);
}
    if (type && type !== 'Tümü') {
        query += ` AND t.type = $${paramIndex++}`;
        values.push(type);
    }
    if (userId && userId !== 'Tümü') {
        query += ` AND t.user_id = $${paramIndex++}`;
        values.push(parseInt(userId));
    }
    if (companyId && companyId !== 'Tümü') {
        if (companyId === 'null') {
            query += ` AND t.company_id IS NULL`;
        } else {
            query += ` AND t.company_id = $${paramIndex++}`;
            values.push(parseInt(companyId));
        }
    }
    if (productId && productId !== 'Tümü') {
        query += ` AND t.product_id = $${paramIndex++}`;
        values.push(parseInt(productId));
    }
    if (searchQuery) {
        const searchPattern = `%${searchQuery.toLowerCase()}%`;
        query += `
            AND (
                LOWER(t.transaction_code) ILIKE $${paramIndex} OR
                LOWER(p.name) ILIKE $${paramIndex} OR
                LOWER(c.name) ILIKE $${paramIndex} OR
                LOWER(u.username) ILIKE $${paramIndex} OR
                LOWER(t.notes) ILIKE $${paramIndex}
            )`;
        values.push(searchPattern);
        paramIndex++;
    }

    query += ` ORDER BY t.transaction_date DESC;`;

    try {
        const { rows } = await pool.query(query, values);

        const formattedRows = await Promise.all(rows.map(async row => {
            let notes = row.transaction_notes;
            if (row.transaction_type === 'adjustment') {
                 const auditLogRes = await pool.query(
    `SELECT old_value, new_value FROM audit_logs
     WHERE table_name = 'transactions' AND record_id = $1 
     ORDER BY timestamp DESC LIMIT 1`,
    [row.transaction_id]
);

                if (auditLogRes.rows.length > 0) {
                    const auditLog = auditLogRes.rows[0];
                    let changeDetails = [];
                    if (auditLog.old_value && auditLog.new_value) {
                        if (auditLog.old_value.stock !== undefined && auditLog.new_value.stock !== undefined) {
                            changeDetails.push(`Stok: ${auditLog.old_value.stock} -> ${auditLog.new_value.stock}`);
                        }
                         if (auditLog.old_value.old_stock !== undefined && auditLog.new_value.new_stock !== undefined) {
                             changeDetails.push(`Stok: ${auditLog.old_value.old_stock} -> ${auditLog.new_value.new_stock}`);
                        }
                    }
                    if (changeDetails.length > 0) {
                        notes = (notes ? notes + ' - ' : '') + `Düzeltme Detayı: (${changeDetails.join(', ')})`;
                    }
                }
            }
            return {
                ...row,
                transaction_notes: notes,
                transaction_date: moment(row.transaction_date).format('DD.MM.YYYY HH:mm:ss')
            };
        }));

        // PDF için HTML şablonu
        
        
        let htmlContent = `
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Begeç Asansör - İşlem Raporu</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Arial', sans-serif;
            font-size: 12px;
            line-height: 1.4;
            color: #333;
            background: #fff;
            margin: 20px;
        }

        /* QR Code and Barcode - Simplified */
        .document-id-section {
            position: absolute;
            top: 10px;
            right: 20px;
            text-align: right;
            font-size: 9px;
        }

        .qr-placeholder {
            width: 40px;
            height: 40px;
            border: 1px solid #666;
            background: #f8f8f8;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 7px;
            margin-bottom: 3px;
            margin-left: auto;
        }

        .document-barcode {
            font-family: 'Courier New', monospace;
            font-size: 7px;
            color: #333;
            border: 1px solid #999;
            padding: 1px 3px;
            background: white;
        }

        /* Enhanced table borders - FIXED */
        table {
            width: 100%;
            border-collapse: collapse;
            border: 2px solid #000;
            margin-top: 20px;
        }

        th {
            padding: 12px 8px;
            font-weight: bold;
            font-size: 11px;
            text-align: left;
            border: 1px solid #000;
            background: #000;
            color: #fff;
        }

        tbody tr {
            border: 1px solid #000;
        }

        tbody tr:nth-child(even) {
            background: #f9f9f9;
        }

        td {
            padding: 10px 8px;
            font-size: 11px;
            border: 1px solid #000;
            vertical-align: top;
        }

        /* Header Section */
        .report-header {
            border-bottom: 3px solid #333;
            padding-bottom: 15px;
            margin-bottom: 20px;
            position: relative;
        }

        .company-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .company-info h1 {
            font-size: 24px;
            font-weight: bold;
            color: #000;
            margin: 0;
        }

        .company-info h2 {
            font-size: 11px;
            color: #666;
            margin: 2px 0 0 0;
            font-weight: normal;
        }

        .report-title {
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            color: #000;
            margin: 15px 0 5px 0;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Meta Information */
        .report-meta {
            background: #f8f8f8;
            border: 1px solid #ddd;
            padding: 15px;
            margin: 20px 0;
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
        }

        .meta-item {
            font-size: 11px;
        }

        .meta-label {
            font-weight: bold;
            color: #000;
            margin-bottom: 3px;
        }

        .meta-value {
            color: #333;
        }

        /* Transaction Type Styling */
        .transaction-type {
            font-weight: bold;
            padding: 3px 6px;
            border-radius: 3px;
            font-size: 10px;
            text-align: center;
            display: inline-block;
            min-width: 50px;
            border: 1px solid #000;
        }

        .type-in {
            background: #f0f0f0;
        }

        .type-out {
            background: #e0e0e0;
        }

        .type-adjustment {
            background: #d0d0d0;
        }

        /* Quantity highlighting */
        .quantity-cell {
            font-weight: bold;
            text-align: right;
        }

        /* Product name cell */
        .product-cell {
            font-weight: 500;
        }

        /* Transaction code styling */
        .transaction-code {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            font-size: 10px;
        }

        /* Date formatting */
        .date-cell {
            white-space: nowrap;
            font-size: 10px;
        }

        .date-main {
            font-weight: bold;
        }

        .date-time {
            color: #666;
        }

        /* Signature Section */
        .signature-section {
            margin-top: 50px;
            page-break-inside: avoid;
        }

        .signature-title {
            text-align: center;
            font-size: 14px;
            font-weight: bold;
            color: #000;
            margin-bottom: 30px;
            text-transform: uppercase;
            border-bottom: 1px solid #333;
            padding-bottom: 5px;
        }

        .signature-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 50px;
            margin-top: 30px;
        }

        .signature-box {
            border: 1px solid #333;
            padding: 20px;
            min-height: 120px;
        }

        .signature-role {
            font-weight: bold;
            text-align: center;
            margin-bottom: 20px;
            font-size: 12px;
            text-transform: uppercase;
        }

        .signature-field {
            margin-bottom: 12px;
            font-size: 11px;
            display: flex;
            justify-content: space-between;
        }

        .signature-label {
            font-weight: bold;
            width: 80px;
        }

        .signature-line {
            border-bottom: 1px solid #333;
            flex: 1;
            margin-left: 10px;
        }

        /* Summary Section */
        .summary-section {
            margin: 30px 0;
            background: #f8f8f8;
            border: 1px solid #ddd;
            padding: 15px;
        }

        .summary-title {
            font-weight: bold;
            margin-bottom: 10px;
            font-size: 12px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            font-size: 11px;
        }

        .summary-item {
            text-align: center;
        }

        .summary-value {
            font-weight: bold;
            font-size: 14px;
            color: #000;
        }

        .summary-label {
            color: #666;
            margin-top: 3px;
        }

        /* Footer */
        .report-footer {
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 10px;
            color: #666;
        }

        /* Multi-page support */
        .page-header {
            display: none;
        }
        
        tbody tr {
            page-break-inside: avoid;
            page-break-after: auto;
        }
        
        thead {
            display: table-header-group;
        }
        
        .summary-section {
            page-break-inside: avoid;
            page-break-after: auto;
        }
        
        .signature-section {
            page-break-inside: avoid;
            page-break-before: auto;
        }

        /* Print optimizations for black-white output */
        @media print {
            body {
                margin: 20mm 15mm 15mm 20mm;
                font-size: 11px;
            }
            
            /* Remove all background colors for print */
            tbody tr:nth-child(even) {
                background: white !important;
            }
            
            tbody tr {
                background: white !important;
            }
            
            .report-meta {
                background: white !important;
                border: 1px solid #000 !important;
            }
            
            .transaction-type {
                background: white !important;
                border: 1px solid #000 !important;
            }
            
            /* Ensure all text is black */
            * {
                color: #000 !important;
            }
            
            /* Keep header backgrounds */
            thead tr {
                background: #000 !important;
                color: #fff !important;
            }
            
            thead th {
                background: #000 !important;
                color: #fff !important;
            }
            
            /* Page header for subsequent pages */
            .page-header {
                display: block;
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                height: 60px;
                background: white;
                border-bottom: 2px solid #333;
                padding: 10px 15mm 10px 20mm;
                margin: 0;
                z-index: 1000;
            }
            
            .page-header .company-name {
                font-size: 16px;
                font-weight: bold;
                margin: 0;
            }
            
            .page-header .report-info {
                font-size: 10px;
                color: #666;
                margin-top: 3px;
            }
            
            /* Adjust body margin for page header */
            body {
                margin-top: 25mm;
            }
            
            /* First page header hidden */
            .report-header {
                page-break-after: avoid;
            }
            
            /* Page numbering */
            @page {
                margin: 20mm 15mm 15mm 20mm;
                size: A4;
                
                @bottom-right {
                    content: "Sayfa " counter(page) " / " counter(pages);
                    font-size: 10px;
                    color: #666;
                }
                
                @bottom-center {
                    content: "Begeç Asansör - İşlem Raporu";
                    font-size: 9px;
                    color: #999;
                }
            }
            
            /* Table page break improvements */
            table {
                border-collapse: collapse;
                border-spacing: 0;
            }
            
            /* Sayfa sonunda tablo biterse alt çizgi */
            table tbody tr:last-child td {
                border-bottom: 2px solid #000;
            }
        }

        @page {
            margin: 15mm;
            size: A4;
        }

        .page-break {
            page-break-after: always;
        }

        /* Status indicators for different companies */
        .company-own {
            font-style: italic;
        }

        .company-external {
            font-weight: normal;
        }

        /* Notes styling */
        .notes-cell {
            font-size: 10px;
            color: #555;
            max-width: 120px;
            word-wrap: break-word;
        }

        /* Detailed Summary Tables */
        .detailed-summary {
            margin: 50px 0;
            page-break-before: always;
        }

        .detailed-summary h2 {
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            color: #000;
            margin-bottom: 30px;
            text-transform: uppercase;
            border-bottom: 3px solid #333;
            padding-bottom: 10px;
        }

        .summary-table {
            width: 100%;
            border-collapse: collapse;
            border: 2px solid #000;
            margin: 30px 0;
        }

        .summary-table th {
            background: #000;
            color: #fff;
            padding: 12px 8px;
            border: 1px solid #000;
            font-size: 11px;
            text-align: center;
        }

        .summary-table td {
            padding: 10px 8px;
            border: 1px solid #000;
            font-size: 11px;
            text-align: center;
        }

        .summary-table tbody tr:nth-child(even) {
            background: #f9f9f9;
        }

        .total-row {
            background: #e0e0e0 !important;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <!-- Header Section -->
    <div class="report-header">
        <div class="company-header">
            <div class="company-info">
                <h1>BEGEÇ ASANSÖR</h1>
                <h2>Asansör İml. İnş. Nak. İth. İhr. San. Tic. Ltd. Şti.</h2>
            </div>
            
            <!-- Document ID and QR Section -->
            <div class="document-id-section">
                <div class="qr-placeholder">
                    QR
                    CODE
                </div>
                <div class="document-barcode">
                    |||| ||| || |||| |||
                </div>
                <div style="font-size: 9px; margin-top: 3px; color: #666;">
                    Rapor No: RPT-${new Date().getFullYear()}${String(new Date().getMonth() + 1).padStart(2, '0')}${String(new Date().getDate()).padStart(2, '0')}-${Math.floor(Math.random() * 1000).toString().padStart(3, '0')}
                </div>
            </div>
        </div>
        
        <div class="report-title">İşlem Raporu</div>
    </div>

    <!-- Report Meta Information -->
    <div class="report-meta">
        <div class="meta-item">
            <div class="meta-label">Rapor Tarihi:</div>
            <div class="meta-value">${moment().format('DD.MM.YYYY HH:mm')}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Oluşturan Kullanıcı:</div>
            <div class="meta-value">${req.user.username}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Tarih Aralığı:</div>
            <div class="meta-value">${startDate ? moment(startDate).format('DD.MM.YYYY') : 'Tümü'} - ${endDate ? moment(endDate).format('DD.MM.YYYY') : 'Tümü'}</div>
        </div>
    </div>

    <!-- Summary Section -->
    <div class="summary-section">
        <div class="summary-title">İşlem Özeti</div>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="summary-value">${formattedRows.length}</div>
                <div class="summary-label">Toplam İşlem</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">${formattedRows.filter(row => row.transaction_type === 'in').length}</div>
                <div class="summary-label">Giriş İşlemi</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">${formattedRows.filter(row => row.transaction_type === 'out').length}</div>
                <div class="summary-label">Çıkış İşlemi</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">${formattedRows.filter(row => row.transaction_type !== 'in' && row.transaction_type !== 'out').length}</div>
                <div class="summary-label">Düzeltme</div>
            </div>
        </div>
    </div>

    <!-- Table Section -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="width: 12%;">İşlem No</th>
                    <th style="width: 12%;">Tarih Saat</th>
                    <th style="width: 8%;">Tip</th>
                    <th style="width: 22%;">Ürün Adı</th>
                    <th style="width: 10%;">Miktar (Birim)</th>
                    <th style="width: 15%;">Firma</th>
                    <th style="width: 8%;">Kullanıcı</th>
                    <th style="width: 13%;">Notlar</th>
                </tr>
            </thead>
            <tbody>
                ${formattedRows.map(row => {
                    // İşlem tipi belirleme
                    let typeClass = 'type-adjustment';
                    let typeText = 'Düzeltme';
                    
                    if (row.transaction_type === 'in') {
                        typeClass = 'type-in';
                        typeText = 'Giriş';
                    } else if (row.transaction_type === 'out') {
                        typeClass = 'type-out';
                        typeText = 'Çıkış';
                    }
                    
                    // Tarih formatı
                    let dateMain, dateTime;
                    
                    if (row.transaction_date) {
                        const dateObj = typeof row.transaction_date === 'string' ? 
                            new Date(row.transaction_date) : row.transaction_date;
                        
                        if (!isNaN(dateObj.getTime())) {
                            dateMain = dateObj.toLocaleDateString('tr-TR');
                            dateTime = dateObj.toLocaleTimeString('tr-TR', {hour: '2-digit', minute: '2-digit', second: '2-digit'});
                        } else {
                            // String formatında tarih varsa (DD.MM.YYYY HH:mm:ss)
                            const parts = row.transaction_date.split(' ');
                            dateMain = parts[0] || row.transaction_date;
                            dateTime = parts[1] || '';
                        }
                    } else {
                        dateMain = '-';
                        dateTime = '';
                    }
                    
                    // Firma tipi belirleme
                    const companyClass = (row.company_name === 'Kendi Üretimi' || !row.company_name) ? 'company-own' : 'company-external';
                    
                    return `
                        <tr>
                            <td><span class="transaction-code">${row.transaction_code || '-'}</span></td>
                            <td class="date-cell">
                                <div class="date-main">${dateMain}</div>
                                <div class="date-time">${dateTime}</div>
                            </td>
                            <td><span class="transaction-type ${typeClass}">${typeText}</span></td>
                            <td class="product-cell">${row.product_name || '-'}</td>
                            <td class="quantity-cell">${row.quantity || '0'} ${row.product_unit_of_measure || ''}</td>
                            <td class="${companyClass}">${row.company_name || 'Kendi Üretimi'}</td>
                            <td>${row.user_username || '-'}</td>
                            <td class="notes-cell">${row.transaction_notes || '-'}</td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    </div>

    <!-- Signature Section - MOVED BEFORE SUMMARY -->
    <div class="signature-section">
        <div class="signature-title">Onay ve İmza</div>
        
        <div class="signature-grid">
            <div class="signature-box">
                <div class="signature-role">Kontrol Eden</div>
                <div class="signature-field">
                    <span class="signature-label">Adı Soyadı:</span>
                    <span class="signature-line"></span>
                </div>
                <div class="signature-field">
                    <span class="signature-label">Unvanı:</span>
                    <span class="signature-line"></span>
                </div>
                <div class="signature-field">
                    <span class="signature-label">Tarih:</span>
                    <span class="signature-line"></span>
                </div>
                <div class="signature-field">
                    <span class="signature-label">İmza:</span>
                    <span class="signature-line"></span>
                </div>
            </div>
            
            <div class="signature-box">
                <div class="signature-role">Onaylayan</div>
                <div class="signature-field">
                    <span class="signature-label">Adı Soyadı:</span>
                    <span class="signature-line"></span>
                </div>
                <div class="signature-field">
                    <span class="signature-label">Unvanı:</span>
                    <span class="signature-line"></span>
                </div>
                <div class="signature-field">
                    <span class="signature-label">Tarih:</span>
                    <span class="signature-line"></span>
                </div>
                <div class="signature-field">
                    <span class="signature-label">İmza:</span>
                    <span class="signature-line"></span>
                </div>
            </div>
        </div>
    </div>

    <!-- DETAILED SUMMARY SECTION - MOVED TO END -->
    <div class="detailed-summary">
        <h2>STOK HAREKETLERİ ÖZETİ</h2>
        
        <!-- İşlem Tipi Bazında Özet -->
        <table class="summary-table">
            <thead>
                <tr>
                    <th>İŞLEM TİPİ</th>
                    <th>ADET</th>
                    <th>GİRİŞ TOPLAM</th>
                    <th>ÇIKIŞ TOPLAM</th>
                    <th>NET DEĞİŞİM</th>
                </tr>
            </thead>
            <tbody>
                ${(() => {
                    const typeGroups = {
                        'URE': { name: '🏭 Üretim', in: 0, out: 0, count: 0 },
                        'SAT': { name: '🛒 Satın Alma', in: 0, out: 0, count: 0 },
                        'SEV': { name: '🚚 Sevkiyat', in: 0, out: 0, count: 0 },
                        'BOM': { name: '⚙️ BOM Tüketimi', in: 0, out: 0, count: 0 },
                        'GIR': { name: '📥 Giriş', in: 0, out: 0, count: 0 },
                        'CIK': { name: '📤 Çıkış', in: 0, out: 0, count: 0 },
                        'DUZ': { name: '🔧 Düzeltme', in: 0, out: 0, count: 0 },
                        'OTHER': { name: '📋 Diğer İşlemler', in: 0, out: 0, count: 0 }
                    };
                    
                    formattedRows.forEach(row => {
                        let code = 'OTHER';
                        
                        // İşlem kodundan prefix'i çıkar
                        if (row.transaction_code) {
                            if (row.transaction_code.includes('-BOM-')) {
                                code = 'BOM';
                            } else {
                                const prefix = row.transaction_code.split('-')[0];
                                if (typeGroups[prefix]) {
                                    code = prefix;
                                }
                            }
                        }
                        
                        const group = typeGroups[code];
                        const qty = parseFloat(row.quantity) || 0;
                        
                        group.count++;
                        
                        // Giriş/Çıkış miktarlarını transaction_type'a göre ayır
                        if (row.transaction_type === 'in') {
                            group.in += Math.abs(qty);
                        } else if (row.transaction_type === 'out') {
                            group.out += Math.abs(qty);
                        } else {
                            // Düzeltmeler için: pozitifse giriş, negatifse çıkış gibi say
                            if (qty > 0) {
                                group.in += qty;
                            } else if (qty < 0) {
                                group.out += Math.abs(qty);
                            }
                        }
                    });
                    
                    let totalIn = 0, totalOut = 0, totalCount = 0;
                    
                    return Object.entries(typeGroups)
                        .filter(([key, data]) => data.count > 0)
                        .map(([key, data]) => {
                            totalIn += data.in;
                            totalOut += data.out;
                            totalCount += data.count;
                            const net = data.in - data.out;
                            const netSymbol = net > 0 ? '▲' : net < 0 ? '▼' : '●';
                            
                            return `
                                <tr>
                                    <td style="text-align: left;">${data.name}</td>
                                    <td>${data.count}</td>
                                    <td>${data.in > 0 ? data.in.toLocaleString('tr') : '-'}</td>
                                    <td>${data.out > 0 ? data.out.toLocaleString('tr') : '-'}</td>
                                    <td style="font-weight: bold;">${netSymbol} ${net.toLocaleString('tr')}</td>
                                </tr>
                            `;
                        }).join('') + `
                        <tr class="total-row">
                            <td style="text-align: left;">📊 TOPLAM</td>
                            <td>${totalCount}</td>
                            <td>${totalIn.toLocaleString('tr')}</td>
                            <td>${totalOut.toLocaleString('tr')}</td>
                            <td style="font-weight: bold;">${totalIn - totalOut > 0 ? '▲' : '▼'} ${(totalIn - totalOut).toLocaleString('tr')}</td>
                        </tr>
                    `;
                })()}
            </tbody>
        </table>

        <!-- Ürün Bazında Özet -->
        <table class="summary-table" style="margin-top: 40px;">
            <thead>
                <tr>
                    <th>ÜRÜN ADI</th>
                    <th>GİRİŞ</th>
                    <th>ÇIKIŞ</th>
                    <th>NET DEĞİŞİM</th>
                </tr>
            </thead>
            <tbody>
                ${(() => {
                    const productSummary = {};
                    
                    formattedRows.forEach(row => {
                        const productName = row.product_name || 'Tanımsız';
                        const unit = row.product_unit_of_measure || '';
                        const quantity = parseFloat(row.quantity) || 0;
                        
                        if (!productSummary[productName]) {
                            productSummary[productName] = {
                                in: 0,
                                out: 0,
                                adjustment: 0,
                                unit: unit
                            };
                        }
                        
                        if (row.transaction_type === 'in') {
                            productSummary[productName].in += quantity;
                        } else if (row.transaction_type === 'out') {
                            productSummary[productName].out += quantity;
                        } else {
                            productSummary[productName].adjustment += quantity;
                        }
                        
                        if (!productSummary[productName].unit && unit) {
                            productSummary[productName].unit = unit;
                        }
                    });
                    
                    return Object.entries(productSummary)
                        .sort(([a], [b]) => a.localeCompare(b, 'tr'))
                        .map(([productName, data], index) => {
                            const inValue = data.in || 0;
                            const outValue = data.out || 0;
                            const adjustmentValue = data.adjustment || 0;
                            const netValue = inValue - outValue + adjustmentValue;
                            const unit = data.unit || '';
                            
                            const netSymbol = netValue > 0 ? '▲' : netValue < 0 ? '▼' : '●';
                            const netStyle = netValue > 0 ? 'font-weight: bold;' : netValue < 0 ? 'font-style: italic;' : '';
                            
                            return `
                                <tr style="${index % 2 === 0 ? '' : 'background: #f9f9f9;'}">
                                    <td style="text-align: left; font-weight: 500;">${productName}</td>
                                    <td>${inValue > 0 ? inValue.toLocaleString('tr') + ' ' + unit : '-'}</td>
                                    <td>${outValue > 0 ? outValue.toLocaleString('tr') + ' ' + unit : '-'}</td>
                                    <td style="${netStyle}">
                                        ${netValue === 0 ? '● 0' : netSymbol + ' ' + (netValue > 0 ? '+' : '') + netValue.toLocaleString('tr') + ' ' + unit}
                                        ${adjustmentValue !== 0 ? '<br><small style="color: #666; font-size: 9px;">(Düz: ' + (adjustmentValue > 0 ? '+' : '') + adjustmentValue.toLocaleString('tr') + ')</small>' : ''}
                                    </td>
                                </tr>
                            `;
                        }).join('');
                })()}
            </tbody>
        </table>
        
        <!-- İstatistik Bilgileri -->
        <div style="margin-top: 30px; text-align: center; font-size: 12px; color: #666; font-weight: 500; border-top: 2px solid #000; padding-top: 15px;">
            ${(() => {
                const uniqueProducts = new Set(formattedRows.map(row => row.product_name || 'Tanımsız'));
                const inCount = formattedRows.filter(row => row.transaction_type === 'in').length;
                const outCount = formattedRows.filter(row => row.transaction_type === 'out').length;
                const uniqueUnits = new Set(formattedRows.map(row => row.product_unit_of_measure).filter(unit => unit));
                return uniqueProducts.size + ' Ürün Çeşidi • ' + inCount + ' Giriş İşlemi • ' + outCount + ' Çıkış İşlemi • ' + uniqueUnits.size + ' Birim Türü';
            })()}
        </div>
    </div>

    <!-- Footer -->
    <div class="report-footer">
        <p>Bu rapor Begeç Asansör Stok Yönetim Sistemi tarafından otomatik olarak oluşturulmuştur.</p>
        <p>Doğruluk oranı: %100 | Son güncelleme: ${new Date().toLocaleDateString('tr-TR')} ${new Date().toLocaleTimeString('tr-TR', {hour: '2-digit', minute: '2-digit'})}</p>
    </div>
</body>
</html>
`;

        

        const options = {
            format: 'A4',
            orientation: 'portrait',
            border: '10mm',
            footer: {
                height: "15mm",
                contents: '<div style="text-align: center; font-size: 8px;">Sayfa {{page}} / {{pages}}</div>'
            }
        };

        pdf.create(htmlContent, options).toBuffer(function(err, buffer) {
            if (err) return next(err);
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="Begec_Asansor_Islem_Raporu_${moment().format('YYYYMMDD_HHmmss')}.pdf"`);
            res.send(buffer);
        });

    } catch (error) {
        console.error('PDF rapor oluşturma hatası:', error);
        next(error);
    }
});

// Raporu CSV olarak dışa aktırma
app.get('/api/reports/transactions/csv', authenticateToken, async (req, res, next) => {
    const {
        startDate,
        endDate,
        type,
        userId,
        companyId,
        productId,
        searchQuery
    } = req.query;

    // Rapor verisini çekmek için /api/reports/transactions endpoint'indeki sorguyu kullan
    let query = `
        SELECT
            p.unit_of_measure AS product_unit_of_measure,
            t.id AS transaction_id,
            t.transaction_code,
            t.transaction_date,
            t.type AS transaction_type,
            t.quantity,
            t.notes AS transaction_notes,
            p.name AS product_name,
            p.barcode AS product_barcode,
            p.stock AS product_current_stock,
            p.min_stock_level AS product_min_stock_level,
            c.name AS company_name,
            cat.name AS category_name,
            u.username AS user_username,
            u.full_name AS user_full_name,
            t.product_stock_after_transaction
        FROM
            transactions t
        LEFT JOIN
            products p ON t.product_id = p.id
        LEFT JOIN
            companies c ON t.company_id = c.id
        LEFT JOIN
            users u ON t.user_id = u.id
        LEFT JOIN
            categories cat ON p.category_id = cat.id
        WHERE 1=1
    `;
    const values = [];
    let paramIndex = 1;

  if (startDate && startDate.trim() !== '' && startDate !== 'undefined' && startDate !== 'null') {
    query += ` AND DATE(t.transaction_date) >= $${paramIndex++}`;
    values.push(startDate);
}
if (endDate && endDate.trim() !== '' && endDate !== 'undefined' && endDate !== 'null') {
    query += ` AND DATE(t.transaction_date) <= $${paramIndex++}`;
    values.push(endDate);
}
    if (type && type !== 'Tümü') {
        query += ` AND t.type = $${paramIndex++}`;
        values.push(type);
    }
    if (userId && userId !== 'Tümü') {
        query += ` AND t.user_id = $${paramIndex++}`;
        values.push(parseInt(userId));
    }
    if (companyId && companyId !== 'Tümü') {
        if (companyId === 'null') {
            query += ` AND t.company_id IS NULL`;
        } else {
            query += ` AND t.company_id = $${paramIndex++}`;
            values.push(parseInt(companyId));
        }
    }
    if (productId && productId !== 'Tümü') {
        query += ` AND t.product_id = $${paramIndex++}`;
        values.push(parseInt(productId));
    }
    if (searchQuery) {
        const searchPattern = `%${searchQuery.toLowerCase()}%`;
        query += `
            AND (
                LOWER(t.transaction_code) ILIKE $${paramIndex} OR
                LOWER(p.name) ILIKE $${paramIndex} OR
                LOWER(c.name) ILIKE $${paramIndex} OR
                LOWER(u.username) ILIKE $${paramIndex} OR
                LOWER(t.notes) ILIKE $${paramIndex}
            )`;
        values.push(searchPattern);
        paramIndex++;
    }

    query += ` ORDER BY t.transaction_date DESC;`;

    try {
        const { rows } = await pool.query(query, values);

        const formattedRows = await Promise.all(rows.map(async row => {
            let notes = row.transaction_notes;
            if (row.transaction_type === 'adjustment') {
                 const auditLogRes = await pool.query(
    `SELECT old_value, new_value FROM audit_logs
     WHERE table_name = 'transactions' AND record_id = $1 
     ORDER BY timestamp DESC LIMIT 1`,
    [row.transaction_id]
);

                if (auditLogRes.rows.length > 0) {
                    const auditLog = auditLogRes.rows[0];
                    let changeDetails = [];
                    if (auditLog.old_value && auditLog.new_value) {
                        if (auditLog.old_value.stock !== undefined && auditLog.new_value.stock !== undefined) {
                            changeDetails.push(`Stok: ${auditLog.old_value.stock} -> ${auditLog.new_value.stock}`);
                        }
                         if (auditLog.old_value.old_stock !== undefined && auditLog.new_value.new_stock !== undefined) {
                             changeDetails.push(`Stok: ${auditLog.old_value.old_stock} -> ${auditLog.new_value.new_stock}`);
                        }
                    }
                    if (changeDetails.length > 0) {
                        notes = (notes ? notes + ' - ' : '') + `Düzeltme Detayı: (${changeDetails.join(', ')})`;
                    }
                }
            }
            return {
                'İşlem Kodu': row.transaction_code || '-',
                'Tarih Saat': moment(row.transaction_date).format('DD.MM.YYYY HH:mm:ss'),
                'İşlem Tipi': row.transaction_type === 'in' ? 'Giriş' : (row.transaction_type === 'out' ? 'Çıkış' : 'Düzeltme'),
                'Miktar': row.quantity,
                'Ürün Adı': row.product_name,
                'Barkod': row.product_barcode,
                'İşlem Sonrası Stok': row.product_stock_after_transaction,
                'Kategori Adı': row.category_name || '-',
                'Firma Adı': row.company_name || 'Kendi Üretimi',
                'Kullanıcı Adı': row.user_username,
                'Notlar': notes || '-'
            };
        }));

        if (formattedRows.length === 0) {
            return res.status(404).json({ message: 'Belirtilen filtrelere uygun veri bulunamadı.' });
        }

        const csvWriter = createObjectCsvWriter({
            path: `./temp_report_${Date.now()}.csv`, // Geçici dosya adı
            header: Object.keys(formattedRows[0]).map(key => ({ id: key, title: key }))
        });

        await csvWriter.writeRecords(formattedRows);

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="Begec_Asansor_Islem_Raporu_${moment().format('YYYYMMDD_HHmmss')}.csv"`);
        fs.createReadStream(csvWriter.options.path).pipe(res);

        // Dosya gönderildikten sonra sil
        res.on('finish', () => {
            fs.unlink(csvWriter.options.path, (err) => {
                if (err) console.error('Geçici CSV dosyası silinirken hata:', err);
            });
        });

    } catch (error) {
        console.error('CSV rapor oluşturma hatası:', error);
        next(error);
    }
});


// ------------------- DENETİM KAYITLARI API'leri -------------------

// Denetim Kayıtlarını Getir (Sadece Admin)
app.get('/api/audit-logs', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page);
        const limit = parseInt(req.query.limit);

        const actualPage = isNaN(page) || page < 1 ? 1 : page;
        const actualLimit = isNaN(limit) || limit < 1 ? 10 : limit;

        const offset = (actualPage - 1) * actualLimit;

        const auditLogsQuery = `
            SELECT al.*, u.username AS user_username_from_users_table
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.timestamp DESC
            LIMIT $1 OFFSET $2;
        `;
        const countQuery = 'SELECT COUNT(*) FROM audit_logs';

        let auditLogsResult;
        try {
            auditLogsResult = await pool.query(auditLogsQuery, [actualLimit, offset]);
        } catch (dbErr) {
            console.error("Veritabanı sorgusu (auditLogsQuery) hatası:", dbErr.message);
            const customError = new Error('Veritabanından denetim günlüklerini çekerken hata oluştu.');
            customError.status = 500;
            customError.originalError = dbErr;
            return next(customError);
        }

        let countResult;
        try {
            countResult = await pool.query(countQuery);
        } catch (dbErr) {
            console.error("Veritabanı sorgusu (countQuery) hatası:", dbErr.message);
            const customError = new Error('Veritabanından denetim günlüklerinin sayısını çekerken hata oluştu.');
            customError.status = 500;
            customError.originalError = dbErr;
            return next(customError);
        }

        const totalItems = parseInt(countResult.rows[0].count);
        const totalPages = Math.ceil(totalItems / actualLimit);

        res.json({
            auditLogs: auditLogsResult.rows,
            currentPage: actualPage,
            totalPages: totalPages,
            totalItems: totalItems
        });
    } catch (err) {
        console.error("Audit Logs API içinde genel hata yakalandı:", err.message);
        next(err);
    }
});


// Frontend dosyalarını sunma kısmı (BU KISIM TÜM API ROTAlarından SONRA GELMELİDİR)
app.use(express.static(path.join(__dirname, 'public'))); // 'public' klasöründeki statik dosyaları sunar

// Tüm diğer GET istekleri için (tanımlı API rotaları dışındaki) index.html dosyasını gönder.
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// YENİ: Product Context Rules Management

// Context rule ekleme
app.post('/api/admin/product-context', authenticateToken, isAdmin, async (req, res, next) => {
    const { product_id, context } = req.body;
    
    if (!product_id || !context || !['purchase', 'production', 'both'].includes(context)) {
        return next(Object.assign(new Error('Geçerli product_id ve context gerekli.'), { status: 400 }));
    }
    
    try {
        // Mevcut kuralı sil
        await pool.query('DELETE FROM product_context_rules WHERE product_id = $1', [product_id]);
        
        // Yeni kural ekle
        if (context === 'both') {
            await pool.query('INSERT INTO product_context_rules (product_id, context) VALUES ($1, $2), ($1, $3)', 
                [product_id, 'purchase', 'production']);
        } else {
            await pool.query('INSERT INTO product_context_rules (product_id, context) VALUES ($1, $2)', 
                [product_id, context]);
        }
        
        // acquisition_methods güncelle
        const methods = context === 'both' ? '["purchase", "production"]' : 
                       context === 'purchase' ? '["purchase"]' : '["production"]';
        await pool.query('UPDATE products SET acquisition_methods = $1 WHERE id = $2', [methods, product_id]);
        
        res.json({ message: 'Context rule başarıyla güncellendi.' });
    } catch (err) {
        next(err);
    }
});

// Context rules listele
app.get('/api/admin/product-context', authenticateToken, isAdmin, async (req, res, next) => {
    try {
        const query = `
            SELECT 
                p.id, p.name, p.acquisition_methods,
                COALESCE(
                    CASE 
                        WHEN p.acquisition_methods = '["purchase", "production"]' THEN 'both'
                        WHEN p.acquisition_methods = '["purchase"]' THEN 'purchase'  
                        WHEN p.acquisition_methods = '["production"]' THEN 'production'
                        ELSE 'both'
                    END, 'both'
                ) as context
            FROM products p 
            WHERE p.is_active = TRUE
            ORDER BY p.name
        `;
        const result = await pool.query(query);
        res.json({ products: result.rows });
    } catch (err) {
        next(err);
    }
});

// GENEL HATA YAKALAYICI (Express uygulamalarında en sonda olmalı)
app.use((err, req, res, next) => {
    // Enhanced error logging
    console.error("\n--- !!! GENEL HATA YAKALANDI !!! ---");
    console.error("İstek URL:", req.originalUrl);
    console.error("Method:", req.method);
    console.error("Hata Mesajı:", err.message || 'Bilinmeyen bir hata oluştu.');
    console.error("Hata Statüsü:", err.status || 500);
    if (err.error_code) console.error("Hata Kodu:", err.error_code);
    if (err.details) console.error("Hata Detayları:", JSON.stringify(err.details, null, 2));
    console.error("Hata Stack Trace:\n", err.stack);
    console.error("--- HATA SONU ---\n");

    // Check if response already sent
    if (res.headersSent) {
        return next(err); // Express'in varsayılan hata işleyicisine bırak
    }

    // Build standardized error response
    const errorResponse = {
        message: err.message || 'Sunucuda beklenmedik bir hata oluştu.',
        error_code: err.error_code || 'INTERNAL_SERVER_ERROR'
    };

    // Add details for specific error types
    if (err.details) {
        errorResponse.details = err.details;
    }

    // Development mode: Add technical details
    if (process.env.NODE_ENV === 'development') {
        errorResponse.stack = err.stack;
        errorResponse.status = err.status || 500;
        
        // Original error bilgisi varsa ekle
        if (err.originalError) {
            errorResponse.originalError = {
                message: err.originalError.message,
                stack: err.originalError.stack
            };
        }
    }

    // Send standardized JSON response
    res.status(err.status || 500).json(errorResponse);
});

// Sunucuyu başlatma
// initializeDatabase fonksiyonunu çağırarak veritabanı bağlantısını ve tablo oluşturmayı başlat
// Sadece test ortamı değilse sunucuyu dinlemeye başla
// Development Test Function - Production'da kaldırılacak
async function testBomIntegration() {
    if (process.env.NODE_ENV === 'production') return;
    
    console.log('\n🧪 BOM Integration Test Starting...');
    console.log('='.repeat(50));
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // Test BOM calculation for product ID 1
        const requirements = await calculateRecursiveBOM(1, 2, client);
        
        console.log(`\n📋 BOM Test Results:`);
        if (requirements.length === 0) {
            console.log('❌ No BOM found for product 1');
        } else {
            requirements.forEach(req => {
                console.log(`📦 ${req.product_name}: ${req.total_quantity_required} ${req.unit_of_measure} (Stock: ${req.current_stock})`);
            });
            
            const validation = validateStockRequirements(requirements);
            console.log(`\n✅ Stock Validation: ${validation.isValid ? 'PASSED' : 'FAILED'}`);
            if (!validation.isValid) {
                validation.errors.forEach(err => console.log(`❌ ${err}`));
            }
        }
        
        await client.query('ROLLBACK');
        console.log('\n🧪 BOM Test Completed');
        console.log('='.repeat(50));
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ BOM Test Failed:', error.message);
    } finally {
        client.release();
    }
}

// Test'i server start'ta çağır (development'ta)
if (process.env.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'test') {
    // Server başladıktan 5 saniye sonra test çalıştır
    setTimeout(testBomIntegration, 5000);
}

if (process.env.NODE_ENV !== 'test') {
  initializeDatabase().then(() => {
      app.listen(PORT, () => {
          console.log(`🚀 Sunucu http://localhost:${PORT} adresinde çalışıyor.`);
      });
  }).catch(err => {
      console.error('Uygulama başlatılırken bir hata oluştu:', err);
      process.exit(1); // Hata durumunda uygulamayı kapat
  });
}
