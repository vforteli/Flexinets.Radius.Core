﻿using System;

namespace Flexinets.Radius.Core
{
    public static class Utils
    {
        /// <summary>
        /// Convert a string of hex encoded bytes to a byte array
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] StringToByteArray(string hex)
        {
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }


        /// <summary>
        /// Convert a byte array to a string of hex encoded bytes
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string ToHexString(this byte[] bytes)
        {
            return BitConverter.ToString(bytes).ToLowerInvariant().Replace("-", "");
        }


        /// <summary>
        /// Get the mccmnc as a string from a 3GPP-User-Location-Info vendor attribute.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static (LocationType locationType, string? mccmnc) GetMccMncFrom3GPPLocationInfo(byte[] bytes)
        {
            string? mccmnc = null;
            var type = (LocationType)bytes[0];
            if (type == LocationType.CGI || type == LocationType.ECGI || type == LocationType.RAI ||
                type == LocationType.SAI || type == LocationType.TAI || type == LocationType.TAIAndECGI)
            {
                var mccDigit1 = (bytes[1] & 15).ToString();
                var mccDigit2 = ((bytes[1] & 240) >> 4).ToString();
                var mccDigit3 = (bytes[2] & 15).ToString();

                var mncDigit1 = (bytes[3] & 15).ToString();
                var mncDigit2 = ((bytes[3] >> 4)).ToString();
                var mncDigit3 = (bytes[2] >> 4).ToString();

                mccmnc = mccDigit1 + mccDigit2 + mccDigit3 + mncDigit1 + mncDigit2;
                if (mncDigit3 != "15")
                {
                    mccmnc = mccmnc + mncDigit3;
                }
            }

            return (type, mccmnc);
        }
    }
}