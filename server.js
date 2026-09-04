const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();

app.use(cors({ origin: true }));
app.use(express.json());

// -----------------------------------------------------------------------------
// 1. FIREBASE ADMIN SDK INITIALIZATION
// -----------------------------------------------------------------------------
if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_PRIVATE_KEY) {
  console.error("CRITICAL ERROR: Firebase Admin environment variables missing!");
  process.exit(1);
}

const formattedPrivateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: formattedPrivateKey,
  }),
});

const db = admin.firestore();

// -----------------------------------------------------------------------------
// 2. FIXED TIER PRICING CONFIGURATION (Matches Screenshot UI)
// -----------------------------------------------------------------------------
const LOCKED_TIER_PRICES = {
  cobra: 0,         // Free Plan
  lieutenant: 3500, // ₦3,500
  commander: 4500,  // ₦4,500
  general: 6000,    // ₦6,000
};

// -----------------------------------------------------------------------------
// 3. SECURITY & UTILITIES
// -----------------------------------------------------------------------------
function verifySquadSignature(req) {
  const squadSignature = req.headers['x-squad-encrypted-body'] || req.headers['x-squad-signature'];
  if (!squadSignature || !process.env.SQUAD_WEBHOOK_SECRET) return false;

  const hash = crypto
    .createHmac('sha512', process.env.SQUAD_WEBHOOK_SECRET)
    .update(JSON.stringify(req.body))
    .digest('hex')
    .toUpperCase();

  return hash === squadSignature.toUpperCase();
}

function calculateWithdrawalFee(amount) {
  if (amount >= 1000 && amount <= 10000) return 300;
  if (amount > 10000) return 500;
  throw new Error("Invalid withdrawal amount. Minimum is ₦1,000.");
}

// -----------------------------------------------------------------------------
// 4. API ENDPOINTS
// -----------------------------------------------------------------------------

/**
 * HEALTH CHECK: Verify server is alive and talking to DB
 */
app.get('/api/health', async (req, res) => {
  try {
    await db.collection('apps').limit(1).get();
    return res.status(200).json({
      status: "online",
      message: "Server is live and connected to Firestore.",
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return res.status(500).json({
      status: "degraded",
      error: "Server running, but Firestore failed.",
      details: error.message
    });
  }
});

/**
 * PAYMENT INITIALIZATION: Generate Checkout URL or Assign Free Tier
 */
app.post('/api/payment/initialize', async (req, res) => {
  try {
    const { email, amount, payment_type, tier_id, app_id, user_id } = req.body;

    if (!app_id || !user_id || !email) {
      return res.status(400).json({ error: "Missing required parameters (app_id, user_id, email)." });
    }

    let finalAmount = 0;

    if (payment_type === 'tier') {
      const normalizedTier = (tier_id || '').toLowerCase();
      if (LOCKED_TIER_PRICES[normalizedTier] === undefined) {
        return res.status(400).json({ error: "Invalid tier upgrade selected." });
      }

      finalAmount = LOCKED_TIER_PRICES[normalizedTier];

      // Handle Free Tier (Cobra) Instantly without Squad
      if (finalAmount === 0) {
        const userRef = db.collection('apps').doc(app_id).collection('users').doc(user_id);
        await userRef.set({
          tier: normalizedTier,
          tierUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        return res.status(200).json({
          success: true,
          message: `Successfully assigned ${normalizedTier} (Free Plan).`,
          free_tier: true
        });
      }
    } else {
      if (!amount || Number(amount) < 500) {
        return res.status(400).json({ error: "Minimum top-up amount is ₦500." });
      }
      finalAmount = Number(amount);
    }

    const transactionRef = `${app_id}_${payment_type}_${user_id}_${Date.now()}`;
    const payload = {
      email,
      amount: finalAmount * 100, // Squad uses Kobo
      currency: "NGN",
      initiate_type: "inline",
      transaction_ref: transactionRef,
      metadata: { app_id, user_id, payment_type, tier_id: tier_id || null },
    };

    const response = await axios.post(
      `${process.env.SQUAD_BASE_URL}/transaction/initiate`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${process.env.SQUAD_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    return res.status(200).json({
      success: true,
      transaction_ref: transactionRef,
      amount: finalAmount,
      checkout_url: response.data.data.checkout_url, // Explicit Checkout URL
      squad_data: response.data.data,
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to initialize payment gateway.", details: error.message });
  }
});

/**
 * PAYMENT VERIFICATION: Manual check
 */
app.post('/api/payment/verify', async (req, res) => {
  try {
    const { transaction_ref } = req.body;
    if (!transaction_ref) return res.status(400).json({ error: "Transaction reference required." });

    const response = await axios.get(
      `${process.env.SQUAD_BASE_URL}/transaction/verify/${transaction_ref}`,
      { headers: { Authorization: `Bearer ${process.env.SQUAD_SECRET_KEY}` } }
    );

    const squadData = response.data.data;
    if (response.data.status === 200 && squadData.transaction_status === 'success') {
      const processed = await processSuccessfulPayment(squadData);
      return res.status(200).json({ success: true, status: 'success', data: processed });
    } else {
      return res.status(400).json({ success: false, status: squadData.transaction_status });
    }
  } catch (error) {
    return res.status(500).json({ error: "Error verifying transaction." });
  }
});

/**
 * WEBHOOK ROUTER: Process auto-callbacks
 */
app.post('/api/webhooks/squad', async (req, res) => {
  if (!verifySquadSignature(req)) {
    return res.status(400).send("Invalid signature header.");
  }

  const { event, data } = req.body;
  try {
    if (event === 'charge.success' || event === 'virtual_account.credited') {
      await processSuccessfulPayment(data);
    }
    return res.status(200).json({ status: "success", message: "Webhook processed." });
  } catch (err) {
    return res.status(500).send("Webhook internal server error.");
  }
});

/**
 * CORE PAYMENT PROCESSOR
 */
async function processSuccessfulPayment(data) {
  const transactionRef = data.transaction_ref || data.transaction_reference;
  const metadata = data.metadata || {};
  const appId = metadata.app_id || transactionRef.split('_')[0];
  const userId = metadata.user_id || transactionRef.split('_')[2];
  const paymentType = metadata.payment_type || transactionRef.split('_')[1];

  if (!appId || !userId) throw new Error("Missing context metadata.");

  const amountPaidInNaira = Number(data.amount || data.transaction_amount) / 100;
  const txRefDoc = db.collection('apps').doc(appId).collection('transactions').doc(transactionRef);

  return await db.runTransaction(async (transaction) => {
    const docSnapshot = await transaction.get(txRefDoc);
    if (docSnapshot.exists && docSnapshot.data().status === 'success') {
      return { already_processed: true };
    }

    const userRef = db.collection('apps').doc(appId).collection('users').doc(userId);

    if (paymentType === 'tier') {
      const tierId = metadata.tier_id || 'upgraded';
      transaction.set(userRef, { tier: tierId, tierUpdatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    } else {
      transaction.set(userRef, {
        walletBalance: admin.firestore.FieldValue.increment(amountPaidInNaira),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
    }

    transaction.set(txRefDoc, {
      transactionRef, userId, appId, amount: amountPaidInNaira, type: paymentType || 'topup',
      status: 'success', channel: data.payment_method || 'squad', processedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { success: true, creditedAmount: amountPaidInNaira };
  });
}

/**
 * CREATE VIRTUAL ACCOUNT
 */
app.post('/api/virtual-account/create', async (req, res) => {
  try {
    const { first_name, last_name, mobile_num, email, bvn, dob, gender, address, customer_identifier } = req.body;
    
    if (!first_name || !last_name || !mobile_num || !email) {
      return res.status(400).json({ error: "Missing basic required fields." });
    }

    const payload = {
      first_name, last_name, mobile_num, email, bvn, dob, gender, address, customer_identifier
    };

    const response = await axios.post(
      `${process.env.SQUAD_BASE_URL}/virtual-account`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${process.env.SQUAD_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    return res.status(200).json({ success: true, virtual_account_data: response.data.data });
  } catch (error) {
    return res.status(500).json({ error: "Failed to create virtual account.", details: error.response?.data || error.message });
  }
});

/**
 * ACCOUNT LOOKUP API
 */
app.post('/api/withdraw/account-lookup', async (req, res) => {
  try {
    const { bank_code, account_number } = req.body;
    if (!bank_code || !account_number) return res.status(400).json({ error: "Bank code and account number required." });

    const response = await axios.post(
      `${process.env.SQUAD_BASE_URL}/payout/account/lookup`,
      { bank_code, account_number },
      { headers: { Authorization: `Bearer ${process.env.SQUAD_SECRET_KEY}`, 'Content-Type': 'application/json' } }
    );

    return res.status(200).json({ success: true, data: response.data.data });
  } catch (error) {
    return res.status(500).json({ error: "Could not resolve bank account details." });
  }
});

/**
 * WITHDRAWAL REQUEST API
 */
app.post('/api/withdraw/request', async (req, res) => {
  try {
    const { app_id, user_id, amount, bank_code, account_number, account_name } = req.body;
    const requestedAmount = Number(amount);

    if (!app_id || !user_id || !requestedAmount || requestedAmount < 1000) {
      return res.status(400).json({ error: "Minimum withdrawal amount is ₦1,000." });
    }

    const fee = calculateWithdrawalFee(requestedAmount);
    const totalDeduction = requestedAmount + fee;
    const userRef = db.collection('apps').doc(app_id).collection('users').doc(user_id);

    await db.runTransaction(async (transaction) => {
      const userDoc = await transaction.get(userRef);
      if (!userDoc.exists) throw new Error("User record not found.");
      
      const currentBalance = userDoc.data().walletBalance || 0;
      if (currentBalance < totalDeduction) {
        throw new Error(`Insufficient funds. Need ₦${totalDeduction}, balance is ₦${currentBalance}.`);
      }
      transaction.update(userRef, { walletBalance: admin.firestore.FieldValue.increment(-totalDeduction) });
    });

    const transferRef = `WDR_${app_id}_${user_id}_${Date.now()}`;
    try {
      await axios.post(
        `${process.env.SQUAD_BASE_URL}/payout/transfer`,
        { remark: "Withdrawal", bank_code, account_number, account_name, amount: (requestedAmount * 100).toString(), transaction_reference: transferRef, currency_id: "NGN" },
        { headers: { Authorization: `Bearer ${process.env.SQUAD_SECRET_KEY}`, 'Content-Type': 'application/json' } }
      );

      await db.collection('apps').doc(app_id).collection('withdrawals').doc(transferRef).set({
        transferRef, userId: user_id, requestedAmount, fee, totalDeducted: totalDeduction, bankCode: bank_code, accountNumber: account_number, accountName: account_name, status: 'success', createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      return res.status(200).json({ success: true, message: "Withdrawal processed.", amountSent: requestedAmount, feeCharged: fee, transferRef });
    } catch (payoutError) {
      await userRef.update({ walletBalance: admin.firestore.FieldValue.increment(totalDeduction) });
      return res.status(502).json({ error: "Payout failed. Wallet refunded.", details: payoutError.response?.data?.message || payoutError.message });
    }
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }
});

/**
 * ADMIN STATS: View summary of users and system health
 */
app.get('/api/admin/stats', async (req, res) => {
  try {
    const appId = req.query.app_id || 'nairamaster';
    
    // Using simple count queries for performance
    const usersSnapshot = await db.collection('apps').doc(appId).collection('users').count().get();
    const transactionsSnapshot = await db.collection('apps').doc(appId).collection('transactions').count().get();

    return res.status(200).json({
      success: true,
      stats: {
        total_users: usersSnapshot.data().count,
        total_transactions: transactionsSnapshot.data().count,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch admin stats." });
  }
});

// -----------------------------------------------------------------------------
// 5. SERVER STARTUP
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(` Central Server running on port ${PORT}`);
  console.log(` Webhook URL: /api/webhooks/squad`);
  console.log(`====================================================`);
});

// Secure Addition: Bank Account Lookup Route
app.post('/api/payout/account-lookup', async (req, res) => {
  try {
    const { bank_code, account_number } = req.body;
    if (!bank_code || !account_number) {
      return res.status(400).json({ error: 'bank_code and account_number are required.' });
    }
    const response = await axios.get('https://api.squadco.com/payout/account/lookup', {
      params: { bank_code, account_number },
      headers: {
        'Authorization': `Bearer ${process.env.SQUAD_SECRET_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    res.json(response.data);
  } catch (error) {
    res.status(error.response?.status || 500).json({
      error: 'Failed to lookup account.',
      details: error.response?.data || error.message
    });
  }
});
