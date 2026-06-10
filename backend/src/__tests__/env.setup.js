// Runs before any module is loaded — sets env vars for the test DB
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://rope_user:devpassword_changeme@localhost:5432/rope_db';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.JWT_SECRET = 'test_jwt_secret_32chars_minimum_xxxxxxxxxxxxxxx';
process.env.JWT_EXPIRES_IN = '1h';
process.env.OTP_BYPASS_ENABLED = 'true';
process.env.OTP_BYPASS_CODE = '123456';
process.env.SERVER_PEPPER = 'test_pepper_change_for_prod_xxxxx';
