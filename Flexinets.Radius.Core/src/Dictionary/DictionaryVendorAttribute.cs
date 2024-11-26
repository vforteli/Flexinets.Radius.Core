namespace Flexinets.Radius.Core
{
    public class DictionaryVendorAttribute : DictionaryAttribute
    {
        public readonly uint VendorId;
        public readonly uint VendorCode;


        /// <summary>
        /// Create a dictionary vendor specific attribute
        /// </summary>
        public DictionaryVendorAttribute(uint vendorId, string name, uint vendorCode, string type) : base(name, 26,
            type)
        {
            VendorId = vendorId;
            VendorCode = vendorCode;
        }
    }
}