namespace Flexinets.Radius.Core
{
    public interface IRadiusDictionary
    {
        /// <summary>
        /// Get a vendor specific attribute by vendorId and vendorCode
        /// </summary>
        DictionaryVendorAttribute? GetVendorAttribute(uint vendorId, byte vendorCode);


        /// <summary>
        /// Get an RFC attribute by code
        /// </summary>
        DictionaryAttribute? GetAttribute(byte code);


        /// <summary>
        /// Get an attribute or vendor attribute by name
        /// </summary>
        DictionaryAttribute? GetAttribute(string name);
    }
}