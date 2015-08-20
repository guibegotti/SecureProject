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

	/**
	 * Uses the openFileOutput() method to create a file in an application data directory 
	 * and set the permissionto with MODE_PRIVATE so that other apps cannot access the file
	 * and checked that it is included in IMAGE_DIRECTORY
	 */
	
	private String filename = "myFile"
	private String string = "private data"
	FileOutputStream fos = null;
	 
	try {
	   fos = openFileOutput(filename, Context.MODE_PRIVATE);
	   fos.write(string.getBytes());
	   fos.close();
	} catch (FileNotFoundException e) {
	  // handle FileNotFoundException
	} catch (IOException e) {
	  // handle IOException
	} finally {
	  if (fos != null) {
		try {
		  fos.close();
		} catch (IOException e) {
		}
	  }
	}
	
	/**
	 * The remember-me functionality is implemented here by storing the user name 
	 * and a secure random string in the cookie. 
	 */
	 
	protected void doPost(HttpServletRequest request,
    HttpServletResponse response) {
    
	String username = request.getParameter("username");
	char[] password = request.getParameter("password").toCharArray();
	boolean rememberMe = Boolean.valueOf(request.getParameter("rememberme"));
	LoginService loginService = new LoginServiceImpl();
	boolean validated = false;
	if (rememberMe) {
		if (request.getCookies()[0] != null &&
			request.getCookies()[0].getValue() != null) {

			String[] value = request.getCookies()[0].getValue().split(";");

			if (!loginService.mappingExists(value[0], value[1])) 
			{
				// (username, random) pair is checked
				// Set error and return
			} 
			else 
			{
			  validated = loginService.isUserValid(username, password);
		 
			  if (!validated) 
			  {
				// Set error and return
			  }
			}
				 
			String newRandom = loginService.getRandomString();
			// Reset the random every time
			loginService.mapUserForRememberMe(username, newRandom);
			HttpSession session = request.getSession();
			session.invalidate();
			session = request.getSession(true);
			// Set session timeout to 15 minutes
			session.setMaxInactiveInterval(60 * 15);
			// Store user attribute and a random attribute in session scope
			session.setAttribute("user", loginService.getUsername());
			Cookie loginCookie =
			  new Cookie("rememberme", username + ";" + newRandom);
			response.addCookie(loginCookie);
	  } 
	  else 
	  {
		// No remember-me functionality selected
		validated = loginService.isUserValid(username, password);
		if (!validated) 
		{
			// Set error and return
		}
	  }
	  Arrays.fill(password, ' ');
	}
		
}