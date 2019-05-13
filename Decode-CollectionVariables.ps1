$Source = @"
using System;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;

public class CollectionVariableDecoder
{
	public static string Decode(string encodedString)
	{
		try
		{
			byte[] array = new byte[encodedString.Length / 2 - 4];
			for (int i = 0; i < encodedString.Length / 2 - 4; i++)
			{
				array[i] = Convert.ToByte(encodedString.Substring((i + 4) * 2, 2), 16);
			}
			return Encoding.Unicode.GetString(ProtectedData.Unprotect(array, null, DataProtectionScope.CurrentUser));
		}
		catch
		{
			return "Something failed.";
		}
	}
}
"@
Try {
    Add-Type -TypeDefinition $Source -ReferencedAssemblies System.Security.dll
    $Query = Get-WmiObject -Query "SELECT * FROM CCM_CollectionVariable" -Namespace "root\ccm\policy\Machine\ActualConfig"
    [xml]$xmlDoc = $Query.Value
    $collVar = $xmlDoc.PolicySecret.InnerText
    [CollectionVariableDecoder]::Decode($collVar)
}
Catch {
    throw "Failed to decode collection variable. Reason:`r`n$_"
}
