package password_validator;
import java.util.Scanner;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.IOException;

/*
*author : Andrew Pfalz
*  date : 7/2/18
*  usage:
*     To build project from project root directory run:
*         `mvn package`
*
*     To execute built package from `target/classes/` run:
*         `java password_validator.Password_Validator`
*/



public class Password_Validator{

    //Make an instance of Scanner to handle user input. It will get closed inside of main() when program exits.
    public static Scanner reader = new Scanner(System.in);

    //Method for checking if string is ascii printable.
    public static boolean isAsciiPrintable(String str) {
        if (str == null) {
            return false;
        }
        int sz = str.length();
        for (int i = 0; i < sz; i++) {
            if (isAsciiPrintable(str.charAt(i)) == false) {
                return false;
            }
        }
        return true;
    }

    //Checks if char is asciiprintable
    public static boolean isAsciiPrintable(char ch) {
        //Allow only space through tilde to get through.
        return ch >= 32 && ch < 127;
    }

    public static String  get_input(){
        //Get input from user, reject non-printing ascii characters and empty strings.
        String raw_passwd = "";
        String    message = "\n\n\n\n\n\n" + "Please enter a password. \nor enter \"q\" to quit.\n>> ";


        while(true){
            System.out.print(message);

            //Update message after printing to make it more responsive.
            message    = "\n\nPrevious entry was invalid. Please enter another password >> ";

            //Get raw password.
            raw_passwd = reader.nextLine();

            //Reject if anything outside of printable ascii is found.
            if (!isAsciiPrintable(raw_passwd)){
                System.out.println("Encountered invalid non-printable ascii character. Rejecting password.");
            }

            //I assumed that an empty string is an invalid password.
            else if (raw_passwd.isEmpty()){
                System.out.print("Password cannot be blank.");
            }else{
                //If entered passwords passed both tests, return it to main() to be further tested.
                break;
            }
        }
        return raw_passwd;
    }

    public static Boolean check_simple_reqs(String candidate){
        //Check for length, letters, uppercase, and digits.
        Boolean has_min_len = false;
        Boolean   has_upper = false;
        Boolean  has_number = false;
        int     num_letters = 0;

        //Check for minimum length.
        if (candidate.length() >= 12){
            has_min_len = true;
        }

        char cur_letter;
        //Check other requirements.
        for (int i=0; i<candidate.length(); i++){
            cur_letter = candidate.charAt(i);
            //Check for upper case letters.
            if (Character.isUpperCase(cur_letter)){
                has_upper = true;
            }
            // Check for numbers.
            if (Character.isDigit(cur_letter)){
                has_number = true;
            }
            //Check for minimum number of letters.
            if (Character.isLetter(cur_letter)){
                num_letters++;
            }
        }
        if (!has_min_len){
            System.out.println("Password must have at least 12 characters.");
            return false;
        }

        if (!has_upper){
            System.out.println("Password must contain at least 1 upper case letter.");
            return false;
        }

        if (!has_number){
            System.out.println("Password must contain at least 1 number.");
            return false;
        }

        if (num_letters == 0){
            System.out.println("Password must contain at least 1 letter.");
            return false;
        }

        //If all tests passed.
        return true;

    }

    public static String string_to_hex(String candidate){
        //Convert hash of password to hex string so it can be compared to response from api.
        try{
            MessageDigest digest    = MessageDigest.getInstance("SHA-1");

            //Hash the candidate password, convert it to hex.
            byte[]        hash      = digest.digest(candidate.getBytes(StandardCharsets.UTF_8));

            StringBuffer hex_string = new StringBuffer();

            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) hex_string.append('0');
                hex_string.append(hex);
            }
            return hex_string.toString();
        }
        catch(Exception ex){
            System.out.println(ex);
            System.out.println("Could not make instance of MessageDigest.");
            return "";
        }
    }

    public static Boolean check_for_pwnage(String full_hash) {
        //Check haveibeenpwned.com to see if entered password appears in list of leaked password.

        String   hash_prefix = "";
        String   hash_suffix = "";
        String[] suffixes;
        Boolean  is_match    = false;


        //Split full_hash into first five characters and rest of hash.
        for (int i=0; i<full_hash.length(); i++){
            if (i < 5){
                hash_prefix += full_hash.charAt(i);
            }else{
                hash_suffix += full_hash.charAt(i);
            }
        }

        try{
            //Make a request to the api.
            URL               url = new URL("https://api.pwnedpasswords.com/range/" + hash_prefix);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");

            //Check response code.
            int status = con.getResponseCode();

            if (status == 200){
                //Read the response.
                BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
                String         input_line;
                String         full_response = "";

                //Matches come back as hex suffix followed by a colon and the number of times the suffix appears in the db.
                //Split each result and keep only the hash, append it to full_response.
                while ((input_line = in.readLine()) != null) {
                    String temp   = input_line.split(":")[0];
                    full_response = full_response + temp.toLowerCase() + "\n";
                }

                //Close http connection and InputStreamReader.
                in.close();
                con.disconnect();

                //Fill suffixes with hash suffixes.
                suffixes = full_response.split("\n");

                //I observed that the hashes come back sorted.
                Boolean     done = false;
                int       cursor = 0;
                int          len = hash_suffix.length();
                int      num_suf = suffixes.length;
                String  cur_hash;

                //Get the int value of the first character in hash_suffix.
                int suffix_first = Integer.decode("0x" + hash_suffix.substring(0,1));

                //Search for matches in suffixes.
                while(done == false && cursor < num_suf){
                    cur_hash = suffixes[cursor];

                    //Get int value of first character in each cur_hash.
                    int cur_first  = Integer.decode("0x" + cur_hash.substring(0,1));


                    if (cur_first > suffix_first){
                        //We know there are no matches in remaining suffixes, because they are sorted.
                        //So break early and return false.
                        done = true;
                        break;
                    }

                    //If first character is below or matches first character,
                    //look for mismatched characters in the rest of the hash.
                    for(int i=0;i<len;i++){

                        //Move on to next potential suffix if we find a mismatch.
                        if (cur_hash.charAt(i) != hash_suffix.charAt(i)){
                            cursor++;
                            break;

                        //If we get to the end of the string without a mismatch, the strings match, return true.
                        }else if(i == len - 1){
                            System.out.println("found match");
                            System.out.println(cur_hash + " " + hash_suffix);
                            done     = true;
                            is_match = true;
                        }
                    }
                }
            }else{
                //If api responded with any code besides 200.
                System.out.println("Request to havebeenpwned did not complete successfully. Do you have a network connection?");
            }
        }catch(Exception ex){
            ex.printStackTrace();
            System.out.println("malformed url");
            is_match = null;
        }
        return is_match;

    }

    public static void write_to_disk(String password) {
        //If the password passes all tests, append it to passwords.txt. If the file doesn't exist. Create it.
        try{
            String      output_fn = "passwords.txt";
            BufferedWriter writer = new BufferedWriter(new FileWriter(output_fn, true));
            writer.write(password + "\n");
            writer.close();
        }catch(Exception ex){
            System.out.println(ex);
            System.out.println("Failed to save the file. Do you have permission to write to this directory?");
        }
    }

    public static void main(String[] args){
        /* Algorithm overview:
         *      Get input from user.
         *      Check that the input passes all tests.
         *      If it does, write it to disk.
         *      Prompt user for another password.
         */
        while (true){
            //Reset state.
            Boolean     success = false;
            Boolean compromised = null;

            //First get the raw password from the user. Reject it only if the input string is empty.
            String   raw_passwd = get_input();

            //Allow for quitting gracefully.
            //Don't allow users to enter "q" as a password since it would be invalid anyway.
            if (raw_passwd.equals("q")){
                System.out.println("\n\n\nQuitting now...");
                reader.close();
                System.exit(0);
            }

            //Check if it passes the simple requirements.
            success             = check_simple_reqs(raw_passwd);

            if(success){
                //Get hex string of sha-1 hash of raw password.
                String     hash = string_to_hex(raw_passwd);

                //Check if password exists in haveibeenpwned.
                compromised     = check_for_pwnage(hash);
            }else{
                System.out.println("Password fails to meet criteria.");
            }
            if(compromised != null && !compromised){
                System.out.println("\n\n\nPassword accepted as valid!");
                System.out.println("Wrote password to passwords.txt.");
                write_to_disk(raw_passwd);
            }
        }
    }
}
