using System;
using System.Linq;

namespace Flexinets.Radius.Core
{
    public class VendorSpecificAttribute
    {
        public readonly byte Length;
        public readonly uint VendorId;
        public readonly byte VendorCode;
        public readonly byte[] Value;


        /// <summary>
        /// Create a vsa from bytes
        /// </summary>
        /// <param name="contentBytes"></param>
        public VendorSpecificAttribute(byte[] contentBytes)
        {
            VendorId = BitConverter.ToUInt32(contentBytes.Take(4).Reverse().ToArray(), 0);
            VendorCode = contentBytes[4];
            Length = contentBytes[5];
            Value = contentBytes.Skip(6).ToArray();
        }
    }
}