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

public class Password_Validator{



    public static String get_input(){
        Boolean      done = false;
        String raw_passwd = "";
        String    message = "\n\n\n\n\n\n" + "Please enter a password. \n or enter \"q\" to quit.\n>> ";

        //make an instance of Scanner to handle user input
        Scanner    reader = new Scanner(System.in);


        while(!done){
            System.out.print(message);

            //update message after printing to make it more responsive.
            message    = "\n\n Previous entry was invalid.\nPlease enter another password >> ";

            //get raw password
            raw_passwd = reader.nextLine();

            //I assumed that an empty string is an invalid password.
            if (raw_passwd.isEmpty()){
                System.out.print("Password cannot be blank.");
            }else{
                //if user inputs a non-empty string, return it to main()
                done = true;
            }
        }
        return raw_passwd;
    }

    public static Boolean check_simple_reqs(String candidate){
        Boolean has_min_len = false;
        Boolean has_upper   = false;
        Boolean has_number  = false;
        int     num_letters = 0;

        //check for minimum length
        if (candidate.length() > 12){
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


        else if(has_min_len && has_upper && has_number && num_letters>= 1){
            return true;
        }else{
            return false;
        }

    }

    public static String string_to_hex(String candidate){
        try{
            MessageDigest digest    = MessageDigest.getInstance("SHA-1");

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
            System.out.println("could not make instance of MessageDigest");
            return "";
        }
    }

    public static Boolean check_for_breech(String full_hash) {

        String   hash_prefix = "";
        String   hash_suffix = "";
        String[] suffixes;
        Boolean  is_match    = false;


        //partition full_hash into first five characters and rest of hash
        for (int i=0; i<full_hash.length(); i++){
            if (i < 5){
                hash_prefix += full_hash.charAt(i);
            }else{
                hash_suffix += full_hash.charAt(i);
            }
        }

        //make a request to the api
        try{
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

                while ((input_line = in.readLine()) != null) {
                    String temp   = input_line.split(":")[0];
                    full_response = full_response + temp.toLowerCase() + "\n";
                }

                in.close();
                con.disconnect();

                // System.out.println(full_response);
                suffixes = full_response.split("\n");

                //assuming the hashes come back sorted.
                Boolean     done = false;
                int       cursor = 0;
                int          len = hash_suffix.length();
                int      num_suf = suffixes.length;
                String  cur_hash;

                while(done == false && cursor < num_suf){
                    cur_hash = suffixes[cursor];
                    for(int i=0;i<len;i++){
                        if (cur_hash.charAt(i) != hash_suffix.charAt(i)){
                            cursor++;
                            break;
                        }else if(i == len - 1){
                            System.out.println("found match");
                            System.out.println(cur_hash + " " + hash_suffix);
                            done     = true;
                            is_match = true;
                        }
                    }
                }
            }
        }catch(Exception e){
            System.out.println("malformed url");
        }
        return is_match;

    }


    public static void write_to_disk(String password) {
        try{
            String      output_fn = "passwords.txt";
            BufferedWriter writer = new BufferedWriter(new FileWriter(output_fn, true));
            writer.write(password + "\n");
            writer.close();
        }catch(Exception e){
            System.out.println("failed to save the file");
        }
    }









    public static void main(String[] args){
        Boolean        done = false;

        while (!done){
            //reset state
            Boolean     success = false;
            Boolean comprimised = null;

            //first get the raw password from the user. reject it only if the input string is empty.
            String   raw_passwd = get_input();

            //allow for quitting gracefully.
            if (raw_passwd.equals("q")){
                System.out.println("\n\n\nQuitting now...");
                System.exit(0);

            }

            //then check if it passes the simple requirements
            success             = check_simple_reqs(raw_passwd);

            if(success){
                //get hex string of sha-1 hash of raw password.
                String     hash = string_to_hex(raw_passwd);

                //check if password exists in haveibeenpwned
                comprimised     = check_for_breech(hash);
            }else{
                System.out.println("Password fails to meet criteria");
            }
            if(comprimised != null && !comprimised){
                System.out.println("\n\n\nPassword accepted as valid!");
                write_to_disk(raw_passwd);
            }
        }

    }
}
