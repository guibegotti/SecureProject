 /**
  *Os códigos abaixos são meros exemplos de como se programar garantindo
  *a segurança dos dados do usuário e integridade da aplicação produzida!
  */
  
public class FunctionsExamples 
{

	/**
	 * The path is decoded by Uri.decode() before use, 
	 * And canonicalized by File.getCanonicalPath() 
	 * and checked that it is included in IMAGE_DIRECTORY
	 * @author Guilherme Begotti
	 */
	 
	private static String IMAGE_DIRECTORY = localFile.getAbsolutePath();
  	public ParcelFileDescriptor openFile(Uri paramUri, String paramString)
    	throws FileNotFoundException 
		{
    		String decodedUriString = Uri.decode(paramUri.toString());
    		File file = new File(IMAGE_DIRECTORY, Uri.parse(decodedUriString).getLastPathSegment());
    		if (file.getCanonicalPath().indexOf(localFile.getCanonicalPath()) != 0) 
			{
      			throw new IllegalArgumentException();
    		}
    		return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
  		}
}