#!/usr/bin/env node

/**
 * OTP Service Test Script
 * Purpose: Test OTP generation, storage, verification, and DB operations
 * Usage: node backend/test-otp-service.js
 */

const { pool } = require('./config/mysql-db');
const { generateOTP, storeOTP, verifyOTP } = require('./utils/otpService');
require('dotenv').config();

// Color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function section(title) {
  log('\n' + '═'.repeat(60), 'blue');
  log(`  ${title}`, 'bright');
  log('═'.repeat(60), 'blue');
}

async function testDatabaseConnection() {
  section('TEST 1: Database Connection');

  try {
    const [rows] = await pool.execute('SELECT 1 as test');
    log('✅ Database connection successful', 'green');
    log(`   Result: ${JSON.stringify(rows[0])}`, 'cyan');
    return true;
  } catch (error) {
    log('❌ Database connection failed', 'red');
    log(`   Error: ${error.message}`, 'red');
    return false;
  }
}

async function testTableExists() {
  section('TEST 2: OTPs Table Existence');

  try {
    const [tables] = await pool.execute("SHOW TABLES LIKE 'otps'");

    if (tables.length > 0) {
      log('✅ otps table exists', 'green');

      // Show table structure
      const [columns] = await pool.execute('DESCRIBE otps');
      log('\n   Table Structure:', 'cyan');
      columns.forEach(col => {
        log(`   - ${col.Field} (${col.Type}) ${col.Null === 'NO' ? 'NOT NULL' : 'NULL'}`, 'blue');
      });

      // Show indexes
      const [indexes] = await pool.execute('SHOW INDEX FROM otps');
      const indexNames = [...new Set(indexes.map(idx => idx.Key_name))];
      log('\n   Indexes:', 'cyan');
      indexNames.forEach(idx => {
        log(`   - ${idx}`, 'blue');
      });

      return true;
    } else {
      log('❌ otps table does not exist', 'red');
      log('   Run migration: node backend/migrations/run-migration.js', 'yellow');
      return false;
    }
  } catch (error) {
    log('❌ Error checking table', 'red');
    log(`   Error: ${error.message}`, 'red');
    return false;
  }
}

async function testOTPGeneration() {
  section('TEST 3: OTP Generation');

  try {
    const otp1 = await generateOTP();
    const otp2 = await generateOTP();
    const otp3 = await generateOTP();

    log(`✅ Generated OTP 1: ${otp1}`, 'green');
    log(`✅ Generated OTP 2: ${otp2}`, 'green');
    log(`✅ Generated OTP 3: ${otp3}`, 'green');

    // Validate OTP format
    const isValid = /^\d{6}$/.test(otp1);

    if (isValid) {
      log('✅ OTP format valid (6 digits)', 'green');
    } else {
      log('❌ OTP format invalid', 'red');
      return false;
    }

    // Check uniqueness
    if (otp1 !== otp2 && otp2 !== otp3 && otp1 !== otp3) {
      log('✅ OTPs are unique', 'green');
    } else {
      log('⚠️  Warning: Generated duplicate OTPs (rare but possible)', 'yellow');
    }

    return otp1;
  } catch (error) {
    log('❌ OTP generation failed', 'red');
    log(`   Error: ${error.message}`, 'red');
    return null;
  }
}

async function testOTPStorage(testEmail, otp, type = 'signup') {
  section(`TEST 4: OTP Storage (${type})`);

  try {
    log(`   Email: ${testEmail}`, 'cyan');
    log(`   OTP: ${otp}`, 'cyan');
    log(`   Type: ${type}`, 'cyan');

    const result = await storeOTP(testEmail, otp, type);

    if (result.success) {
      log('✅ OTP stored successfully', 'green');
      log(`   Message: ${result.message}`, 'cyan');

      // Verify in database
      const [rows] = await pool.execute(
        'SELECT * FROM otps WHERE email = ? AND otp = ? AND type = ?',
        [testEmail, otp, type]
      );

      if (rows.length > 0) {
        log('✅ OTP verified in database', 'green');
        log(`   Record ID: ${rows[0].id}`, 'cyan');
        log(`   Expires at: ${rows[0].expires_at}`, 'cyan');
        log(`   Is used: ${rows[0].is_used}`, 'cyan');
      } else {
        log('⚠️  OTP not found in database (might be in JSON fallback)', 'yellow');
      }

      return true;
    } else {
      log('❌ OTP storage failed', 'red');
      log(`   Message: ${result.message}`, 'red');
      return false;
    }
  } catch (error) {
    log('❌ Error storing OTP', 'red');
    log(`   Error: ${error.message}`, 'red');
    return false;
  }
}

async function testOTPVerification(testEmail, otp, type = 'signup', shouldPass = true) {
  section(`TEST 5: OTP Verification (should ${shouldPass ? 'pass' : 'fail'})`);

  try {
    log(`   Email: ${testEmail}`, 'cyan');
    log(`   OTP: ${otp}`, 'cyan');
    log(`   Type: ${type}`, 'cyan');

    const result = await verifyOTP(testEmail, otp, type);

    if (result.valid === shouldPass) {
      log(`✅ Verification ${shouldPass ? 'passed' : 'failed'} as expected`, 'green');
      log(`   Message: ${result.message}`, 'cyan');
      return true;
    } else {
      log(`❌ Verification ${shouldPass ? 'failed' : 'passed'} unexpectedly`, 'red');
      log(`   Expected: ${shouldPass}, Got: ${result.valid}`, 'red');
      log(`   Message: ${result.message}`, 'red');
      return false;
    }
  } catch (error) {
    log('❌ Error verifying OTP', 'red');
    log(`   Error: ${error.message}`, 'red');
    return false;
  }
}

async function testOTPReuse(testEmail, otp, type = 'signup') {
  section('TEST 6: OTP Reuse Prevention');

  try {
    log('   Attempting to reuse the same OTP...', 'cyan');

    const result = await verifyOTP(testEmail, otp, type);

    if (!result.valid) {
      log('✅ OTP reuse prevented successfully', 'green');
      log(`   Message: ${result.message}`, 'cyan');
      return true;
    } else {
      log('❌ OTP was reused (security issue!)', 'red');
      return false;
    }
  } catch (error) {
    log('❌ Error testing OTP reuse', 'red');
    log(`   Error: ${error.message}`, 'red');
    return false;
  }
}

async function testMultipleTypes(testEmail) {
  section('TEST 7: Multiple OTP Types');

  try {
    const types = ['signup', 'login', 'password-reset'];
    const otps = {};

    // Generate and store OTPs for different types
    for (const type of types) {
      const otp = await generateOTP();
      otps[type] = otp;

      log(`   Storing ${type} OTP: ${otp}`, 'cyan');
      const result = await storeOTP(testEmail, otp, type);

      if (!result.success) {
        log(`❌ Failed to store ${type} OTP`, 'red');
        return false;
      }
    }

    // Verify each OTP with correct type
    for (const type of types) {
      const result = await verifyOTP(testEmail, otps[type], type);

      if (result.valid) {
        log(`✅ ${type} OTP verified successfully`, 'green');
      } else {
        log(`❌ ${type} OTP verification failed`, 'red');
        return false;
      }
    }

    log('✅ Multiple OTP types handled correctly', 'green');
    return true;
  } catch (error) {
    log('❌ Error testing multiple types', 'red');
    log(`   Error: ${error.message}`, 'red');
    return false;
  }
}

async function testCleanup(testEmail) {
  section('TEST 8: Cleanup Test Records');

  try {
    const [result] = await pool.execute(
      'DELETE FROM otps WHERE email = ?',
      [testEmail]
    );

    log(`✅ Cleaned up ${result.affectedRows} test records`, 'green');
    return true;
  } catch (error) {
    log('❌ Error cleaning up', 'red');
    log(`   Error: ${error.message}`, 'red');
    return false;
  }
}

async function showStatistics() {
  section('DATABASE STATISTICS');

  try {
    // Total OTPs
    const [total] = await pool.execute('SELECT COUNT(*) as count FROM otps');
    log(`   Total OTPs: ${total[0].count}`, 'cyan');

    // Active OTPs
    const [active] = await pool.execute(
      'SELECT COUNT(*) as count FROM otps WHERE expires_at > NOW() AND is_used = FALSE'
    );
    log(`   Active OTPs: ${active[0].count}`, 'cyan');

    // Expired OTPs
    const [expired] = await pool.execute(
      'SELECT COUNT(*) as count FROM otps WHERE expires_at <= NOW()'
    );
    log(`   Expired OTPs: ${expired[0].count}`, 'cyan');

    // Used OTPs
    const [used] = await pool.execute(
      'SELECT COUNT(*) as count FROM otps WHERE is_used = TRUE'
    );
    log(`   Used OTPs: ${used[0].count}`, 'cyan');

    // OTPs by type
    const [types] = await pool.execute(
      'SELECT type, COUNT(*) as count FROM otps GROUP BY type'
    );
    log('\n   OTPs by Type:', 'cyan');
    types.forEach(row => {
      log(`   - ${row.type}: ${row.count}`, 'blue');
    });

  } catch (error) {
    log('⚠️  Could not fetch statistics', 'yellow');
    log(`   Error: ${error.message}`, 'yellow');
  }
}

async function runAllTests() {
  const testEmail = `test_${Date.now()}@example.com`;
  let passedTests = 0;
  let totalTests = 0;

  log('\n╔════════════════════════════════════════════════════════╗', 'bright');
  log('║          MEDSCORE OTP Service Test Suite             ║', 'bright');
  log('╚════════════════════════════════════════════════════════╝', 'bright');

  try {
    // Test 1: Database Connection
    totalTests++;
    if (await testDatabaseConnection()) passedTests++;
    else {
      log('\n❌ Cannot proceed without database connection', 'red');
      return;
    }

    // Test 2: Table Exists
    totalTests++;
    if (await testTableExists()) passedTests++;
    else {
      log('\n❌ Cannot proceed without otps table', 'red');
      log('💡 Run: node backend/migrations/run-migration.js', 'yellow');
      return;
    }

    // Test 3: OTP Generation
    totalTests++;
    const otp = await testOTPGeneration();
    if (otp) passedTests++;
    else {
      log('\n❌ Cannot proceed without OTP generation', 'red');
      return;
    }

    // Test 4: OTP Storage
    totalTests++;
    if (await testOTPStorage(testEmail, otp, 'signup')) passedTests++;

    // Test 5: OTP Verification (should pass)
    totalTests++;
    if (await testOTPVerification(testEmail, otp, 'signup', true)) passedTests++;

    // Test 6: OTP Reuse Prevention
    totalTests++;
    if (await testOTPReuse(testEmail, otp, 'signup')) passedTests++;

    // Test 7: Wrong OTP (should fail)
    totalTests++;
    if (await testOTPVerification(testEmail, '999999', 'signup', false)) passedTests++;

    // Test 8: Multiple Types
    totalTests++;
    if (await testMultipleTypes(testEmail)) passedTests++;

    // Statistics
    await showStatistics();

    // Cleanup
    await testCleanup(testEmail);

  } catch (error) {
    log('\n💥 Fatal error during tests:', 'red');
    console.error(error);
  } finally {
    // Results
    section('TEST RESULTS');

    const percentage = Math.round((passedTests / totalTests) * 100);

    log(`\n   Tests Passed: ${passedTests}/${totalTests} (${percentage}%)`,
        passedTests === totalTests ? 'green' : 'yellow');

    if (passedTests === totalTests) {
      log('\n   🎉 All tests passed! OTP service is working correctly.', 'green');
    } else {
      log(`\n   ⚠️  ${totalTests - passedTests} test(s) failed. Please investigate.`, 'yellow');
    }

    // Close connection
    await pool.end();
    log('\n   🔌 Database connection closed.', 'blue');
    log('\n✨ Test suite completed!\n', 'cyan');
  }
}

// Run tests
runAllTests().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
