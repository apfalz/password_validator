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

        //make an instance of Scanner to handle user input
        Scanner reader = new Scanner(System.in);

        //get raw password
        System.out.println("Please enter a password >>");
        return reader.next();
    }

    public static Boolean check_simple_reqs(String candidate){
        Boolean has_min_len = false;
        Boolean has_upper   = false;
        Boolean has_number  = false;
        int     num_letters = 0;

        //check for minimum length
        if (candidate.length() < 12){
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
        if(has_upper && has_number && num_letters>= 1){
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
                System.out.println("successfully made a connection to api");

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
                Boolean done     = false;
                int     cursor   = 0;
                int     len      = hash_suffix.length();
                int     num_suf  = suffixes.length;
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
        System.out.println("attempting to cache password");
        try{
            String  output_fn   = "successful_passwords.txt";
            BufferedWriter writer = new BufferedWriter(new FileWriter(output_fn, true));
            writer.write(password + "\n");
            writer.close();
            System.out.println("wrote successful password to disk");
        }catch(Exception e){
            System.out.println("failed to save the file");
        }
    }









    public static void main(String[] args){
        Boolean success = false;
        Boolean result  = false;
        String raw_passwd = get_input();

        success           = check_simple_reqs(raw_passwd);

        if(success){
            System.out.println("passed simple requirements");

            String hash       = string_to_hex(raw_passwd);

            result            = check_for_breech(hash);
        }
        if(!result){
            System.out.println("did not find password on haveibeenpwned.");
            write_to_disk(raw_passwd);
        }

    }
}
