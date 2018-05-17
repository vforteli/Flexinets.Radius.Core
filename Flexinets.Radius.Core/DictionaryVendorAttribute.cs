using System;

namespace Flexinets.Radius.Core
{
    public class DictionaryVendorAttribute : DictionaryAttribute
    {
        public readonly UInt32 VendorId;
        public readonly UInt32 VendorCode;


        /// <summary>
        /// Create a dictionary vendor specific attribute
        /// </summary>
        /// <param name="vendorId"></param>
        /// <param name="name"></param>
        /// <param name="vendorCode"></param>        
        /// <param name="type"></param>
        public DictionaryVendorAttribute(UInt32 vendorId, String name, UInt32 vendorCode, String type) : base(name, 26, type)
        {
            VendorId = vendorId;
            VendorCode = vendorCode;
        }
    }
}
