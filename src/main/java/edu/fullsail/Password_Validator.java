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

    //make an instance of Scanner to handle user input.
    //it will get closed inside of main() when program exits.
    public static Scanner reader = new Scanner(System.in);

    public static String  get_input(){
        String raw_passwd = "";
        String    message = "\n\n\n\n\n\n" + "Please enter a password. \n or enter \"q\" to quit.\n>> ";


        while(true){
            System.out.print(message);

            //update message after printing to make it more responsive.
            message    = "\n\n Previous entry was invalid.\nPlease enter another password >> ";

            //get raw password
            raw_passwd = reader.nextLine();
            System.out.println("before");
            System.out.println(raw_passwd);

            raw_passwd = raw_passwd.replaceAll("[^\\x20-\\x7E]", "");


            System.out.println(raw_passwd);
            System.out.println(raw_passwd.length());

            //check for arrow keys that were not supressed from shell
            if (raw_passwd.contains("^[[")){


                System.out.println("Found unsupressed arrow keys. Rejecting password.");
            }
            //I am assuming we want to reject non-ascii characters because they could lead to unforseen consequences.
            if (!raw_passwd.matches("\\A\\p{ASCII}*\\z")){
                System.out.println("Found some non-ascii characters. Rejecting password.");
            }

            //I assumed that an empty string is an invalid password.
            else if (raw_passwd.isEmpty()){
                System.out.print("Password cannot be blank.");
            }else{
                //if user inputs a non-empty string, return it to main()
                break;
            }
        }
        return raw_passwd;
    }

    public static Boolean check_simple_reqs(String candidate){
        Boolean has_min_len = false;
        Boolean   has_upper = false;
        Boolean  has_number = false;
        int     num_letters = 0;

        //check for minimum length
        if (candidate.length() >= 12){
            has_min_len = true;
        }

        //check other requirements
        for (int i=0; i<candidate.length(); i++){
            char cur_letter = candidate.charAt(i);
            //check for upper case letters
            if (Character.isUpperCase(cur_letter)){
                has_upper = true;
            }
            // check for numbers
            if (Character.isDigit(cur_letter)){
                has_number = true;
            }
            //check for minimum number of letters
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

        //if all tests passed
        return true;

    }

    public static String string_to_hex(String candidate){
        try{
            MessageDigest digest    = MessageDigest.getInstance("SHA-1");

            //hash the candidate password, convert it to hex.
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

    public static Boolean check_for_breach(String full_hash) {

        String   hash_prefix = "";
        String   hash_suffix = "";
        String[] suffixes;
        Boolean  is_match    = false;


        //split full_hash into first five characters and rest of hash
        for (int i=0; i<full_hash.length(); i++){
            if (i < 5){
                hash_prefix += full_hash.charAt(i);
            }else{
                hash_suffix += full_hash.charAt(i);
            }
        }

        try{

            //make a request to the api
            URL               url = new URL("https://api.pwnedpasswords.com/range/" + hash_prefix);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");

            //check response code
            int status = con.getResponseCode();

            if (status == 200){
                //read the response
                BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
                String         input_line;
                String         full_response = "";

                //matches come back as hex suffix followed by a colon and the number of times the suffix appears in the db.
                //split each result and keep only the hash, append it to full_response.
                while ((input_line = in.readLine()) != null) {
                    String temp   = input_line.split(":")[0];
                    full_response = full_response + temp.toLowerCase() + "\n";
                }

                //close http connection and InputStreamReader
                in.close();
                con.disconnect();

                //fill suffixes with hash suffixes
                suffixes = full_response.split("\n");

                //assuming the hashes come back sorted.
                Boolean     done = false;
                int       cursor = 0;
                int          len = hash_suffix.length();
                int      num_suf = suffixes.length;
                String  cur_hash;
                int suffix_first = Integer.decode(hash_suffix.substring(0,1));

                //search for matches in http response
                while(done == false && cursor < num_suf){
                    cur_hash = suffixes[cursor];

                    //get int value of first character in each cur_hash
                    int cur_first  = Integer.decode(cur_hash.substring(0,1));


                    if (cur_first > suffix_first){
                        //we know there are no results in remaining suffixes, because they are sorted.
                        //so break early and return false
                        done = true;
                        break;
                    }

                    //look for mismatched characters
                    for(int i=0;i<len;i++){

                        //break if we find a mismatch
                        if (cur_hash.charAt(i) != hash_suffix.charAt(i)){
                            cursor++;
                            break;

                        //if we get to the end of the string without a mismatch, the strings match, return true.
                        }else if(i == len - 1){
                            System.out.println("found match");
                            System.out.println(cur_hash + " " + hash_suffix);
                            done     = true;
                            is_match = true;
                        }
                    }
                }
            }
        }catch(Exception ex){
            System.out.println(ex);
            System.out.println("malformed url");
            is_match = null;
        }
        return is_match;

    }

    public static void write_to_disk(String password) {
        try{
            //if password is validated append it to passwords.txt
            String      output_fn = "passwords.txt";
            BufferedWriter writer = new BufferedWriter(new FileWriter(output_fn, true));
            System.out.println(password);
            writer.write(password + "\n");
            writer.close();
        }catch(Exception ex){
            System.out.println(ex);
            System.out.println("Failed to save the file. Do you have permission to write to this directory?");
        }
    }

    public static void main(String[] args){
        while (true){
            //reset state
            Boolean     success = false;
            Boolean compromised = null;

            //first get the raw password from the user. Reject it only if the input string is empty.
            String   raw_passwd = get_input();

            //allow for quitting gracefully.
            //don't allow users to enter "q" as a password since it would be invalid anyways.
            if (raw_passwd.equals("q")){
                System.out.println("\n\n\nQuitting now...");
                reader.close();
                System.exit(0);
            }

            //then check if it passes the simple requirements
            success             = check_simple_reqs(raw_passwd);

            if(success){
                //get hex string of sha-1 hash of raw password.
                String     hash = string_to_hex(raw_passwd);

                //check if password exists in haveibeenpwned
                compromised     = check_for_breach(hash);
            }else{
                System.out.println("Password fails to meet criteria");
            }
            if(compromised != null && !compromised){
                System.out.println("\n\n\nPassword accepted as valid!");
                System.out.println("Wrote password to passwords.txt.");
                write_to_disk(raw_passwd);
            }
        }
    }
}
