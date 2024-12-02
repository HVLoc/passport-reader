/*
 * Copyright 2016 - 2022 Anton Tananaev (anton.tananaev@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
@file:Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")

package vn.lochv.nfc

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.graphics.Bitmap
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.AsyncTask
import android.os.Bundle
import android.preference.PreferenceManager
import android.text.Editable
import android.text.TextWatcher
import android.util.Base64
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import net.sf.scuba.smartcards.CardService
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.util.ASN1Dump
import org.bouncycastle.asn1.x509.Certificate
import org.jmrtd.AccessKeySpec
import org.jmrtd.PACEKeySpec
import org.jmrtd.PassportService
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.ChipAuthenticationPublicKeyInfo
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SODFile
import org.jmrtd.lds.SecurityInfo
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.iso19794.FaceImageInfo
import vn.lochv.nfc.ImageUtil.decodeImage
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Arrays


abstract class MainActivity : AppCompatActivity() {

    private lateinit var passportNumberView: EditText

    private var passportNumberFromIntent = false
    private var encodePhotoToBase64 = false
    private lateinit var mainLayout: View
    private lateinit var loadingLayout: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val preferences = PreferenceManager.getDefaultSharedPreferences(this)

        val passportNumber = intent.getStringExtra("passportNumber")

        encodePhotoToBase64 = intent.getBooleanExtra("photoAsBase64", false)
        if (passportNumber != null) {
            PreferenceManager.getDefaultSharedPreferences(this).edit()
                .putString(KEY_PASSPORT_NUMBER, passportNumber).apply()
            passportNumberFromIntent = true
        }

        passportNumberView = findViewById(R.id.input_passport_number)
        mainLayout = findViewById(R.id.main_layout)
        loadingLayout = findViewById(R.id.loading_layout)

        passportNumberView.setText(preferences.getString(KEY_PASSPORT_NUMBER, null))

        passportNumberView.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable) {
                PreferenceManager.getDefaultSharedPreferences(this@MainActivity).edit()
                    .putString(KEY_PASSPORT_NUMBER, s.toString()).apply()
            }
        })
    }

    override fun onResume() {
        super.onResume()
        val adapter = NfcAdapter.getDefaultAdapter(this)
        if (adapter != null) {
            val intent = Intent(applicationContext, this.javaClass)
            intent.flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            val pendingIntent =
                PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE)
            val filter = arrayOf(arrayOf("android.nfc.tech.IsoDep"))
            adapter.enableForegroundDispatch(this, pendingIntent, null, filter)
        }
        if (passportNumberFromIntent) {
            // When the passport number field is populated from the caller, we hide the
            // soft keyboard as otherwise it can obscure the 'Reading data' progress indicator.
            window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN)
        }
    }

    override fun onPause() {
        super.onPause()
        val adapter = NfcAdapter.getDefaultAdapter(this)
        adapter?.disableForegroundDispatch(this)
    }

    public override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            val tag: Tag? = intent.extras?.getParcelable(NfcAdapter.EXTRA_TAG)
            if (tag?.techList?.contains("android.nfc.tech.IsoDep") == true) {
                val preferences = PreferenceManager.getDefaultSharedPreferences(this)
                val passportNumber = preferences.getString(KEY_PASSPORT_NUMBER, null)

                if (!passportNumber.isNullOrEmpty()) {

                    val paceKeySpec: PACEKeySpec = PACEKeySpec.createCANKey(passportNumber)
                    ReadTask(IsoDep.get(tag), paceKeySpec).execute()
                    mainLayout.visibility = View.GONE
                    loadingLayout.visibility = View.VISIBLE
                } else {
                    Snackbar.make(passportNumberView, R.string.error_input, Snackbar.LENGTH_SHORT)
                        .show()
                }
            }
        }
    }

    @SuppressLint("StaticFieldLeak")
    private inner class ReadTask(
        private val isoDep: IsoDep, private val accessKeySpec: AccessKeySpec
    ) : AsyncTask<Void?, Void?, Exception?>() {

        private lateinit var dg1File: DG1File
        private lateinit var dg2File: DG2File
        private lateinit var dg14File: DG14File
        private lateinit var sodFile: SODFile
        private var imageBase64: String? = null
        private var bitmap: Bitmap? = null
        private var chipAuthSucceeded = false
        private var passiveAuthSuccess = false
        private lateinit var dg14Encoded: ByteArray
        private lateinit var dg13Decoded: String

        override fun doInBackground(vararg params: Void?): Exception? {
            try {
                isoDep.timeout = 10000
                val cardService = CardService.getInstance(isoDep)
                cardService.open()
                val service = PassportService(
                    cardService,
                    PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
                    PassportService.DEFAULT_MAX_BLOCKSIZE,
                    false,
                    false,
                )
                service.open()
                var paceSucceeded = false
                try {
                    val cardAccessFile =
                        CardAccessFile(service.getInputStream(PassportService.EF_CARD_ACCESS))
                    val securityInfoCollection = cardAccessFile.securityInfos
                    for (securityInfo: SecurityInfo in securityInfoCollection) {
                        if (securityInfo is PACEInfo) {
                            service.doPACE(
                                accessKeySpec,
                                securityInfo.objectIdentifier,
                                PACEInfo.toParameterSpec(securityInfo.parameterId),
                                null,
                            )
                            paceSucceeded = true
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, e)
                }
                service.sendSelectApplet(paceSucceeded)
                if (!paceSucceeded) {
                    try {
                        service.getInputStream(PassportService.EF_COM).read()
                    } catch (e: Exception) {
                        service.doBAC(accessKeySpec)
                    }
                }
                val dg1In = service.getInputStream(PassportService.EF_DG1)
                dg1File = DG1File(dg1In)
                val dg2In = service.getInputStream(PassportService.EF_DG2)
                dg2File = DG2File(dg2In)
                val sodIn = service.getInputStream(PassportService.EF_SOD)
                sodFile = SODFile(sodIn)

                val dg13In = service.getInputStream(PassportService.EF_DG13)

                dg13Decoded =  decodeASN1(dg13In)

                doChipAuth(service)
                doPassiveAuth()

                val allFaceImageInfo: MutableList<FaceImageInfo> = ArrayList()
                dg2File.faceInfos.forEach {
                    allFaceImageInfo.addAll(it.faceImageInfos)
                }
                if (allFaceImageInfo.isNotEmpty()) {
                    val faceImageInfo = allFaceImageInfo.first()
                    val imageLength = faceImageInfo.imageLength
                    val dataInputStream = DataInputStream(faceImageInfo.imageInputStream)
                    val buffer = ByteArray(imageLength)
                    dataInputStream.readFully(buffer, 0, imageLength)
                    val inputStream: InputStream = ByteArrayInputStream(buffer, 0, imageLength)
                    bitmap = decodeImage(this@MainActivity, faceImageInfo.mimeType, inputStream)
                    imageBase64 = Base64.encodeToString(buffer, Base64.DEFAULT)
                }
            } catch (e: Exception) {
                return e
            }
            return null
        }

        private fun doChipAuth(service: PassportService) {
            try {
                val dg14In = service.getInputStream(PassportService.EF_DG14)
                dg14Encoded = IOUtils.toByteArray(dg14In)
                val dg14InByte = ByteArrayInputStream(dg14Encoded)
                dg14File = DG14File(dg14InByte)
                val dg14FileSecurityInfo = dg14File.securityInfos

                for (securityInfo: SecurityInfo in dg14FileSecurityInfo) {
                    if (securityInfo is ChipAuthenticationPublicKeyInfo) {
                        service.doEACCA(
                            securityInfo.keyId,
                            ChipAuthenticationPublicKeyInfo.ID_CA_ECDH_AES_CBC_CMAC_256,
                            securityInfo.objectIdentifier,
                            securityInfo.subjectPublicKey,
                        )
                        chipAuthSucceeded = true
                    }
                }

            } catch (e: Exception) {
                Log.w(TAG, e)
            }
        }

        private fun doPassiveAuth() {
            try {
                val digest = MessageDigest.getInstance(sodFile.digestAlgorithm)
                val dataHashes = sodFile.dataGroupHashes
                val dg14Hash = if (chipAuthSucceeded) digest.digest(dg14Encoded) else ByteArray(0)
                val dg1Hash = digest.digest(dg1File.encoded)
                val dg2Hash = digest.digest(dg2File.encoded)

                if (Arrays.equals(dg1Hash, dataHashes[1]) && Arrays.equals(
                        dg2Hash,
                        dataHashes[2]
                    ) && (!chipAuthSucceeded || Arrays.equals(dg14Hash, dataHashes[14]))
                ) {

                    val asn1InputStream = ASN1InputStream(assets.open("masterList"))
                    val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
                    keystore.load(null, null)
                    val cf = CertificateFactory.getInstance("X.509")

                    var p: ASN1Primitive?
                    while (asn1InputStream.readObject().also { p = it } != null) {
                        val asn1 = ASN1Sequence.getInstance(p)
                        if (asn1 == null || asn1.size() == 0) {
                            throw IllegalArgumentException("Null or empty sequence passed.")
                        }
                        if (asn1.size() != 2) {
                            throw IllegalArgumentException("Incorrect sequence size: " + asn1.size())
                        }
                        val certSet = ASN1Set.getInstance(asn1.getObjectAt(1))
                        for (i in 0 until certSet.size()) {
                            val certificate = Certificate.getInstance(certSet.getObjectAt(i))
                            val pemCertificate = certificate.encoded
                            val javaCertificate =
                                cf.generateCertificate(ByteArrayInputStream(pemCertificate))
                            keystore.setCertificateEntry(i.toString(), javaCertificate)
                        }
                    }

                    val docSigningCertificates = sodFile.docSigningCertificates
                    for (docSigningCertificate: X509Certificate in docSigningCertificates) {
                        docSigningCertificate.checkValidity()
                    }

                    val cp = cf.generateCertPath(docSigningCertificates)
                    val pkixParameters = PKIXParameters(keystore)
                    pkixParameters.isRevocationEnabled = false
                    val cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType())
                    cpv.validate(cp, pkixParameters)
                    var sodDigestEncryptionAlgorithm = sodFile.docSigningCertificate.sigAlgName
                    var isSSA = false
                    if ((sodDigestEncryptionAlgorithm == "SSAwithRSA/PSS")) {
                        sodDigestEncryptionAlgorithm = "SHA256withRSA/PSS"
                        isSSA = true
                    }
                    val sign = Signature.getInstance(sodDigestEncryptionAlgorithm)
                    if (isSSA) {
                        sign.setParameter(
                            PSSParameterSpec(
                                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
                            )
                        )
                    }
                    sign.initVerify(sodFile.docSigningCertificate)
                    sign.update(sodFile.eContent)
                    passiveAuthSuccess = sign.verify(sodFile.encryptedDigest)
                }
            } catch (e: Exception) {
                Log.w(TAG, e)
            }
        }

        override fun onPostExecute(result: Exception?) {
            mainLayout.visibility = View.VISIBLE
            loadingLayout.visibility = View.GONE
            if (result == null) {
                val intent = if (callingActivity != null) {
                    Intent()
                } else {
                    Intent(this@MainActivity, ResultActivity::class.java)
                }
                val mrzInfo = dg1File.mrzInfo
                intent.putExtra(
                    ResultActivity.KEY_FIRST_NAME, mrzInfo.secondaryIdentifier.replace("<", " ")
                )
                intent.putExtra(
                    ResultActivity.KEY_LAST_NAME, mrzInfo.primaryIdentifier.replace("<", " ")
                )
                intent.putExtra(ResultActivity.KEY_GENDER, mrzInfo.gender.toString())
                intent.putExtra(ResultActivity.KEY_STATE, mrzInfo.issuingState)
                intent.putExtra(ResultActivity.KEY_NATIONALITY, mrzInfo.nationality)
                intent.putExtra(ResultActivity.KEY_VNM, dg13Decoded)
                val passiveAuthStr = if (passiveAuthSuccess) {
                    getString(R.string.pass)
                } else {
                    getString(R.string.failed)
                }
                val chipAuthStr = if (chipAuthSucceeded) {
                    getString(R.string.pass)
                } else {
                    getString(R.string.failed)
                }
                intent.putExtra(ResultActivity.KEY_PASSIVE_AUTH, passiveAuthStr)
                intent.putExtra(ResultActivity.KEY_CHIP_AUTH, chipAuthStr)
                bitmap?.let { bitmap ->
                    if (encodePhotoToBase64) {
                        intent.putExtra(ResultActivity.KEY_PHOTO_BASE64, imageBase64)
                    } else {
                        val ratio = 320.0 / bitmap.height
                        val targetHeight = (bitmap.height * ratio).toInt()
                        val targetWidth = (bitmap.width * ratio).toInt()
                        intent.putExtra(
                            ResultActivity.KEY_PHOTO,
                            Bitmap.createScaledBitmap(bitmap, targetWidth, targetHeight, false)
                        )
                    }
                }
                if (callingActivity != null) {
                    setResult(RESULT_OK, intent)
                    finish()
                } else {
                    startActivity(intent)
                }
            } else {
                Snackbar.make(passportNumberView, result.toString(), Snackbar.LENGTH_LONG).show()
            }
        }
    }

    companion object {
        private val TAG = MainActivity::class.java.simpleName
        private const val KEY_PASSPORT_NUMBER = "passportNumber"
    }
}


fun decodeASN1(inputStream: InputStream): String
{

    val asn1In = ASN1InputStream(inputStream)
    val asn1Object: ASN1Primitive = asn1In.readObject()
    println("ASN.1 asn1Hex:"+ ASN1Dump.dumpAsString(asn1Object))
    val asn1Hex = ASN1Dump.dumpAsString(asn1Object)

    // Regex để lấy UTF8String hoặc PrintableString
    val regex = Regex("(UTF8String|PrintableString)\\((.*?)\\)")
    val matches = regex.findAll(asn1Hex)

    // Lưu các giá trị được trích xuất
    val listDg13 = matches.mapNotNull { it.groups[2]?.value }.toList()

    // Kết hợp thành chuỗi
    val result = listDg13.joinToString(", ")

    asn1In.close()

    return result;
}

