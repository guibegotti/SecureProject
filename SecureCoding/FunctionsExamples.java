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
	
	/**
	 * If the intent is only broadcast/received in the same application, 
	 * LocalBroadcastManager can be used which reduces the risk of leaking sensitive information.
	 */
	 
  	public final void onReceive(Context context, Intent intent)
  	{
	        intent = new Intent("my-sensitive-event");
	    	if (intent != null && intent.getAction() != null) 
	    	{
	      		String s = intent.getAction();
	      		if (s.equals("com.sample.action.server_running")
	      		{
	        		String ip = intent.getStringExtra("local_ip");
	        		String pwd = intent.getStringExtra("code");
	        		String port = intent.getIntExtra("port", 8888);
	        		boolean status = intent.getBooleanExtra("connected", false);
				intent.putExtra("event", "this is a test event");
				LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
	      		}
	    	}
  	}
	
	/**
	 * The user has to grant permission to use geolocation
	 */
	
	public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions$Callback callback) {
	        if(getBoolean("SECURITY_ENABLE_GEOLOCATION_INFORMATION", true)) {
	            WebView.geo(this.geo).permissionShowPrompt(origin, callback);
	        }
	        else {
	            callback.invoke(origin, false, false);
	        }
	}
	
	/**
	 * Provide a secure communication channel 
	 */
	
	public void generateSocket throws IOException {
		SSLSocket sslSocket = null;
		try 
		{
			SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 9999);
			PrintWriter out = new PrintWriter(sslSocket.getOutputStream(), true);
			BufferedReader in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			String userInput;
			while ((userInput = stdIn.readLine()) != null) 
			{
				out.println(userInput);
				System.out.println(in.readLine());
			}
		} 
		finally 
		{
			if (sslSocket != null) 
			{
				try 
				{
					sslSocket.close();
				} catch (IOException x) {
					//Handle Error
				}
			}
		}
	}
	
	/**
	 * Provide a secure random number 
	 * Ensuring a good seed;
	 */
	
	public static byte[] secureRandom(int size) 
	{
		SecureRandom sr = new SecureRandom();
		byte[] output = new byte[size];
		sr.nextBytes(output);
		return output;
	}
	
	/**
	 * Take control of the operations on your aplication
	 * Like in database, we have to control the operations,
	 * Watch over starvation and deadlocks.
	 */
	
	public void widgetOp() 
	{
		synchronized (widgetList) 
		{
			for (Widget w : widgetList) 
			{
				doSomething(w);
			}
		}
	}
	
	/**
	 * Limit the scope of the @SuppressWarnings annotation 
	 * to the nearest code that generates a warning.
	 */
	
	@SuppressWarnings("unchecked")
	Set s = new HashSet();
	public final void doLogic(int a,char c) 
	{
		s.add(a); // Produces unchecked warning
		s.add(c); // Produces unchecked warning
	}
	
	/**
	 * Use good algorithms and good practices to store user's passwords
	 */
	
	private void setPassword(byte[] pass) throws Exception 
	{
		byte[] salt = generateSalt(12);
		byte[] input = appendArrays(pass, salt);
		MessageDigest msgDigest = MessageDigest.getInstance("SHA-512");
		// Encode the string and salt
		byte[] hashVal = msgDigest.digest(input);  
		clearArray(pass);  
		clearArray(input);
		saveBytes(salt, "salt.bin");  
		// Save the hash value to password.bin
		saveBytes(hashVal,"password.bin");
		clearArray(salt);
		clearArray(hashVal);
	}
	 
	boolean checkPassword(byte[] pass) throws Exception 
	{
		byte[] salt = loadBytes("salt.bin");
		byte[] input = appendArrays(pass, salt);
		MessageDigest msgDigest = MessageDigest.getInstance("SHA-512");
		// Encode the string and salt
		byte[] hashVal1 = msgDigest.digest(input);
		clearArray(pass);
		clearArray(input);
		// Load the hash value stored in password.bin
		byte[] hashVal2 = loadBytes("password.bin");
		boolean arraysEqual = Arrays.equals(hashVal1, hashVal2);
		clearArray(hashVal1);
		clearArray(hashVal2);
		return arraysEqual;
	}
	 
}
