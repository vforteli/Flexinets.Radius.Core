using System;

namespace Flexinets.Radius.Core
{
    public class VendorSpecificAttribute
    {
        public Byte Length;
        public UInt32 VendorId;
        public Byte VendorCode;
        public Type VendorType;
        public Byte[] Value;


        /// <summary>
        /// Create a vsa from bytes
        /// </summary>
        /// <param name="contentBytes"></param>
        public VendorSpecificAttribute(Byte[] contentBytes)
        {
            var vendorId = new Byte[4];
            Buffer.BlockCopy(contentBytes, 0, vendorId, 0, 4);
            Array.Reverse(vendorId);
            VendorId = BitConverter.ToUInt32(vendorId, 0);

            var vendorType = new Byte[1];
            Buffer.BlockCopy(contentBytes, 4, vendorType, 0, 1);
            VendorCode = vendorType[0];

            var vendorLength = new Byte[1];
            Buffer.BlockCopy(contentBytes, 5, vendorLength, 0, 1);
            Length = vendorLength[0];

            var value = new Byte[contentBytes.Length - 6];
            Buffer.BlockCopy(contentBytes, 6, value, 0, contentBytes.Length - 6);
            Value = value;
        }
    }
}
