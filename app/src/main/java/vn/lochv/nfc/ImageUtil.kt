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
package vn.lochv.nfc

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import jj2000.j2k.decoder.Decoder
import jj2000.j2k.util.ParameterList
import org.jnbis.WsqDecoder
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream


object ImageUtil {
    @Throws(IOException::class)
    fun decodeImage(context: Context, mimeType: String, inputStream: InputStream): Bitmap? {
        if (mimeType.equals("image/jp2", ignoreCase = true) || mimeType.equals(
                "image/jpeg2000",
                ignoreCase = true
            )
        ) {
            // Save jp2 file

            val output: OutputStream = FileOutputStream(File(context.cacheDir, "temp.jp2"))
            val buffer = ByteArray(1024)
            var read: Int
            while ((inputStream.read(buffer).also { read = it }) != -1) {
                output.write(buffer, 0, read)
            }
            output.close()

            // Decode jp2 file
            val pinfo = Decoder.getAllParameters()
            val parameters: ParameterList

            val defaults = ParameterList()
            for (i in pinfo.indices.reversed()) {
                if (pinfo[i][3] != null) {
                    defaults[pinfo[i][0]] = pinfo[i][3]
                }
            }

            parameters = ParameterList(defaults)

            parameters.setProperty("rate", "3")
            parameters.setProperty("o", context.cacheDir.toString() + "/temp.ppm")
            parameters.setProperty("debug", "on")

            parameters.setProperty("i", context.cacheDir.toString() + "/temp.jp2")

            val decoder = Decoder(parameters)
            decoder.run()

            // Read ppm file
            val reader = BufferedInputStream(
                FileInputStream(File(context.cacheDir.toString() + "/temp.ppm"))
            )
            if (reader.read() != 'P'.code || reader.read() != '6'.code) return null

            reader.read()
            var widths = ""
            var heights = ""
            var temp: Char
            while ((reader.read().toChar().also { temp = it }) != ' ') widths += temp
            while ((reader.read().toChar()
                    .also { temp = it }) >= '0' && temp <= '9'
            ) heights += temp
            if (reader.read() != '2'.code || reader.read() != '5'.code || reader.read() != '5'.code) return null
            reader.read()

            val width = widths.toInt()
            val height = heights.toInt()
            val colors = IntArray(width * height)

            val pixel = ByteArray(3)
            var len: Int
            var cnt = 0
            var total = 0
            val rgb = IntArray(3)
            while ((reader.read(pixel).also { len = it }) > 0) {
                for (i in 0 until len) {
                    rgb[cnt] = if (pixel[i] >= 0) pixel[i].toInt() else (pixel[i] + 255)
                    if ((++cnt) == 3) {
                        cnt = 0
                        colors[total++] = Color.rgb(rgb[0], rgb[1], rgb[2])
                    }
                }
            }

            return Bitmap.createBitmap(colors, width, height, Bitmap.Config.ARGB_8888)
        } else if (mimeType.equals("image/x-wsq", ignoreCase = true)) {
            val wsqDecoder = WsqDecoder()
            val bitmap = wsqDecoder.decode(inputStream)
            val byteData = bitmap.pixels
            val intData = IntArray(byteData.size)
            for (j in byteData.indices) {
                intData[j] =
                    -0x1000000 or ((byteData[j].toInt() and 0xFF) shl 16) or ((byteData[j].toInt() and 0xFF) shl 8) or (byteData[j].toInt() and 0xFF)
            }
            return Bitmap.createBitmap(
                intData,
                0,
                bitmap.width,
                bitmap.width,
                bitmap.height,
                Bitmap.Config.ARGB_8888
            )
        } else {
            return BitmapFactory.decodeStream(inputStream)
        }
    }
}