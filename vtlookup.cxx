// LibCurl
#define CURL_STATICLIB
#include <curl/curl.h>

// OpenSSL
#include <openssl/sha.h>

// Nlohmann JSON
#include <json.hpp>
using Json = nlohmann::json;

// Standard library
#include <Windows.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <map>

// #define VERBOSE_OUTPUT

/* This function uses OpenSSL to calculate the SHA-256 digest of the provided input data
 * and returns a hexadecimal string representation of the digest.
 * */
std::string Sha256Hexdigest(const std::vector<uint8_t>& input_data) {
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest_buffer;

    SHA256_CTX openssl_sha256;
    SHA256_Init(&openssl_sha256);
    SHA256_Update(&openssl_sha256, input_data.data(), input_data.size());
    SHA256_Final(digest_buffer.data(), &openssl_sha256);

    std::stringstream hexdigest_conversion_stream;
    hexdigest_conversion_stream << std::setfill('0') << std::hex;

    for(const auto& byte : digest_buffer) {
        hexdigest_conversion_stream << std::setw(2) << static_cast<uint32_t>(byte);
    }

    return hexdigest_conversion_stream.str();
}

/*
 * This is a companion function to the GetRequest function. It is provided to LibCurl as a "writer function"
 * meant to accumulate bytes of data received by curl, and append them to a string specified in the GetRequest
 * function when setting the CURLOPT_WRITEDATA option via curl_easy_setopt.
 * */
std::size_t GetRequestWriter(void* data, std::size_t fake_size, std::size_t size, std::string* output_data) {
    output_data->append(reinterpret_cast<char*>(data), fake_size * size);
    return fake_size * size;
}

/* This function uses LibCurl to perform an HTTP/GET request to the specified URL
 * and returns the received data as a string.
 * */
long GetRequest(const std::string& url, std::string* out_body, std::string* out_header) {
    auto curl_handle = curl_easy_init();

    if(curl_handle) {
        curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "curl");
        curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);

        #ifdef VERBOSE_OUTPUT
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
        #endif

        unsigned long http_status_code;

        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &GetRequestWriter);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, out_body);
        curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, out_header);
        curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPALIVE, 2UL);

        curl_easy_perform(curl_handle);

        curl_easy_getinfo(curl_handle, CURLINFO_HTTP_CODE, &http_status_code);

        curl_easy_cleanup(curl_handle);
        curl_handle = nullptr;

        return http_status_code;
    }

    return -1;
}

struct VirusTotalReport {
    // Struct to store scan results of a specific engine.
    struct EngineScan {
        std::string EngineVersion;
        std::string Description;
        std::string EngineName;
        std::string ScanDate;
        bool Detected;
    };

    // Report variables.
    // ==========================================================
    std::vector<VirusTotalReport::EngineScan> EngineScans;

    std::string FileSha256Hexdigest;
    std::string FileSha1Hexdigest;
    std::string FileMd5Hexdigest;
    std::string ErrorMessage;
    std::string ReportLink;
    std::string Resource;
    std::string ScanDate;
    std::string ScanId;

    uint32_t ResponseCode;
    uint32_t Positives;
    uint32_t Negatives;
    uint32_t ScanCount;
    double DetectionRatio;
    // ==========================================================

    std::string ApiKey;

    /* This method uses the provided resource and ApiKey member variable to construct
     * a VirusTotal API query URL, and performs an HTTP/GET request via the GetRequest
     * function to retrieve the results of the query, and returns it as a Json object.
     * */
    long RetrieveJsonReport(const std::string& target_resource, Json* out_json_report, std::string* out_body = nullptr, std::string* out_header = nullptr) {
        std::stringstream request_url_stream;

        request_url_stream << "https://www.virustotal.com/vtapi/v2/file/report";
        request_url_stream << "?apikey=" << ApiKey;
        request_url_stream << "&resource=" << target_resource;

        const std::string request_url = request_url_stream.str();
        request_url_stream.clear();

        std::string response_body, response_header;
        long http_status_code = GetRequest(request_url, &response_body, &response_header);

        Json json_report;

        try {
            json_report = Json::parse(response_body);
            *out_json_report = json_report;
        } catch(nlohmann::detail::exception&) {}

        if(out_body != nullptr) *out_body = response_body;
        if(out_header != nullptr) *out_header = response_header;

        return http_status_code;
    }

    /* This method retrieves and loads a report based on the supplied resource.
     * The resource is typically a hexdigest of the file in question.
     * */
    long LoadReport(const std::string& target_resource, std::string* out_body = nullptr, std::string* out_header = nullptr) {
        Json json_report;

        long http_status_code = RetrieveJsonReport(target_resource, &json_report, out_body, out_header);

        if(http_status_code == 200) {
            try{
                LoadJsonReport(json_report);
            } catch(nlohmann::detail::exception& exception) {
                std::cout << "Exception encountered when trying to call LoadJsonReport from LoadReport." << std::endl;
                std::cout << "Exception message: " << exception.what() << std::endl;
                return -2;
            }
        }

        return http_status_code;
    }

    /* This method takes a Json object representing a VirusTotal report, as returned
     * by RetrieveJsonReport, iterates through the object and loads each key and its
     * value individually into the class's member variables.
     * */
    void LoadJsonReport(const Json& json_report) {
        Clear(); // Clear the report variables to ensure that no old data is present in the new report.

        std::map<std::string, std::string*> string_value_map {
            {"verbose_msg", &(this->ErrorMessage)},
            {"permalink", &(this->ReportLink)},
            {"scan_date", &(this->ScanDate)},
            {"resource", &(this->Resource)},
            {"sha256", &(this->FileSha256Hexdigest)},
            {"sha1", &(this->FileSha1Hexdigest)},
            {"md5", &(this->FileMd5Hexdigest)},
        };

        std::map<std::string, uint32_t*> integer_value_map {
            {"response_code", &(this->ResponseCode)},
            {"positives", &(this->Positives)},
            {"total", &(this->ScanCount)},
        };

        // The primary loading loop that loads the JSON data into corresponding member variables.
        for(const auto& kvpair : json_report.items()) {
            // Use the kvpair's key to look up the corresponding string that should hold the key's value
            // according to string_value_map, e.g. "verbose_msg" key resolves to the ErrorMessage member
            // variable, and so the kvpair's value gets stored in ErrorMessage.
            if(kvpair.value().is_string() && string_value_map.find(kvpair.key()) != string_value_map.end()) {
                *string_value_map.at(kvpair.key()) = std::string(kvpair.value().get<std::string>());
            }

            // Performs the same as the above, except using the integer value map for integer pointers.
            else if(kvpair.value().is_number_integer() && integer_value_map.find(kvpair.key()) != integer_value_map.end()) {
                *integer_value_map.at(kvpair.key()) = kvpair.value().get<uint32_t>();
            }

            // Parses the "scans" structure in the report, and constructs a new EngineScan object for
            // every scan, before emplacing it into the EngineScans vector member variable.
            else if(kvpair.key() == "scans" && kvpair.value().is_structured()) {
                const auto& engine_scans_json_object = kvpair.value();

                for(const auto& engine_scan_kvpair : engine_scans_json_object.items()) {
                    const auto& engine_scan_values = engine_scan_kvpair.value();

                    EngineScan engine_scan_object {
                       engine_scan_values.find("version") != engine_scan_values.end() && engine_scan_values.at("version").is_string() ? engine_scan_values.at("version").get<std::string>() : "NONE GIVEN",
                       engine_scan_values.find("result") != engine_scan_values.end() ? (!engine_scan_values.at("result").is_string() ? "CLEAN" : engine_scan_values.at("result").get<std::string>()) : "NONE GIVEN",
                       engine_scan_kvpair.key(),
                       engine_scan_values.find("update") != engine_scan_values.end() && engine_scan_values.at("update").is_string() ? engine_scan_values.at("update").get<std::string>() : "NONE GIVEN",
                       engine_scan_values.find("detected") != engine_scan_values.end() && engine_scan_values.at("detected").is_boolean() ? engine_scan_values.at("detected").get<bool>() : false
                    };

                    EngineScans.emplace_back(engine_scan_object);
                }
            }
        }

        // Calculates the amount of "negatives" using the amount of positives and total scans,
        // as long as Positives and ScanCount aren't set to their default values, implying their
        // values weren't present in the report.
        if(Positives != 0xFFFFFFFF && ScanCount != 0xFFFFFFFF) {
            Negatives = ScanCount - Positives;

            if(Positives != 0 && ScanCount >= Positives) {
                DetectionRatio = round((static_cast<double>(Positives) / static_cast<double>(ScanCount)) * 100.0);
            } else {
                DetectionRatio = 0;
            }
        }
    }

    void Clear() {
        EngineScans.clear();

        ResponseCode    =   0xFFFFFFFF;
        Positives       =   0xFFFFFFFF;
        Negatives       =   0xFFFFFFFF;
        ScanCount       =   0xFFFFFFFF;

        DetectionRatio  =   -1;

        FileSha256Hexdigest.clear();
        FileSha1Hexdigest.clear();
        ErrorMessage.clear();
        ReportLink.clear();
        Resource.clear();
        ScanDate.clear();
        ScanId.clear();
    }

    VirusTotalReport(const std::string& api_key) {
        ApiKey = api_key;
        Clear();
    }

    ~VirusTotalReport() {
        Clear();
    }
};

int main(int argc, char* argv[]) {
    bool verbose_output = false;    // Enables the verbose output of the VirusTotal report.
    std::string target_hash;        // The hash of the file who's report will be retrieved.
    std::string api_key;            // Api key that will be used to retrieve the report.

    // Loop that handles command line arguments.
    for(int32_t i=0; i<argc; ++i) {
        const char* current_argument = argv[i];
        const char* next_argument = (i+ 1) < argc ? argv[i+1] : nullptr;

        if(!_stricmp(current_argument, "--hash") && next_argument != nullptr) {
            target_hash = std::string(next_argument);
        } else if(!_stricmp(current_argument, "--file") && next_argument != nullptr) {
            std::ifstream file_input_stream(next_argument, std::ios::binary);
            if(file_input_stream.good()) {
                std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(file_input_stream)), (std::istreambuf_iterator<char>()));

                file_input_stream.close();
                target_hash = Sha256Hexdigest(file_data);
            } else {
                std::cout << "Stream to input file is bad; verify the name and path to the file. Cannot continue without a hash." << std::endl;
                return 2;
            }
        } else if(!_stricmp(current_argument, "--api-key") && next_argument != nullptr) {
            api_key = std::string(next_argument);
        } else if(!_stricmp(current_argument, "--verbose")) {
            verbose_output = true;
        }
    }

    if(api_key.size() == 0) {
        std::ifstream file_input_stream("config.json", std::ios::binary);

        if(file_input_stream.good()) {
            std::vector<char> file_data((std::istreambuf_iterator<char>(file_input_stream)), (std::istreambuf_iterator<char>()));
            std::string file_data_string; file_data_string.resize(file_data.size());
            std::copy(file_data.begin(), file_data.end(), file_data_string.begin());

            Json configuration = Json::parse(file_data_string);

            for(const auto& kvpair : configuration.items()) {
                if(kvpair.key() == "api_key") {
                    api_key = kvpair.value().get<std::string>();
                }
            }
        } else {
            std::cout << "Input stream to configuration file is bad. Cannot continue without an API key." << std::endl;
            std::cout << "Generating a new configuration file.." << std::endl;

            std::ofstream file_output_stream("config.json", std::ios::binary);
            if(file_output_stream.good()) {
                Json configuration_template {{"api_key", ""}};
                std::string configuration_template_string = configuration_template.dump(4);

                file_output_stream.write(configuration_template_string.c_str(), configuration_template_string.size());
                file_output_stream.close();

                std::cout << "Configuration file has been generated. Please fill it in and try again." << std::endl;
                return 1;
            } else {
                std::cout << "Output stream to configuration file is bad. Cannot generate a new configuration file." << std::endl;
                return 3;
            }
        }
    }

    if(api_key.size() != 64) {
        std::cout << "A valid API key has a size of 64. The one supplied has a size of " << api_key.size() << " and is therefore invalid. Cannot continue without an API key." << std::endl;
        return 4;
    }

    if(target_hash.size() == 0) {
        std::cout << "No input hash has been supplied." << std::endl;
        return 5;
    }

    VirusTotalReport virus_total_report(api_key);

    std::string response_body, response_header;
    long status_code = virus_total_report.LoadReport(target_hash, &response_body, &response_header);

    if(status_code != 200) {
        std::cout << std::endl << "The status code returned when attempting to load the report is not okay (should be 200): " << status_code << std::endl;
        std::cout << "Negative codes are internal errors, a code 0 is a connection error, and > 0 are HTTP status codes." << std::endl;

        if(status_code > 0) {
            std::cout << "The response header may yield more information, as the code is an HTTP status code.." << std::endl;
            std::cout << std::string(50, '=') << std::endl;
            std::cout << response_header << std::endl;
            return 1;
        }
    }

    HANDLE console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    uint16_t original_text_attributes;

    CONSOLE_SCREEN_BUFFER_INFO console_screen_buffer_info;
    GetConsoleScreenBufferInfo(console_handle, &console_screen_buffer_info);
    original_text_attributes = console_screen_buffer_info.wAttributes;

    if(virus_total_report.ResponseCode == 1) {
        std::cout << std::endl;
        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << std::string(virus_total_report.ReportLink.size(), '=') << std::endl;
        std::cout << virus_total_report.ReportLink << std::endl;
        std::cout << std::string(virus_total_report.ReportLink.size(), '=') << std::endl;
        std::cout << " -> ";

        SetConsoleTextAttribute(console_handle, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << virus_total_report.Positives;

        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " / ";

        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << virus_total_report.ScanCount;
        std::cout << " [" <<  virus_total_report.DetectionRatio << " %]";
        std::cout << " @ " ;
        std::cout << virus_total_report.ScanDate;
        std::cout << " | ";

        SetConsoleTextAttribute(console_handle, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << virus_total_report.Positives << " positives";

        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " & ";
        std::cout << virus_total_report.Negatives << " negatives";
        std::cout << " out of ";

        SetConsoleTextAttribute(console_handle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << virus_total_report.ScanCount;

        SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " distinct antivirus engine scans.." << std::endl;
        std::cout << std::string(virus_total_report.ReportLink.size(), '=') << std::endl;

        SetConsoleTextAttribute(console_handle, original_text_attributes);

        const std::vector<VirusTotalReport::EngineScan>& engine_scans = virus_total_report.EngineScans;

        for(std::size_t i=0; i<engine_scans.size(); ++i) {
            const VirusTotalReport::EngineScan& engine_scan = engine_scans.at(i);
            std::stringstream engine_report_stream;
            engine_report_stream << engine_scan.EngineName << "(" << engine_scan.EngineVersion << ")";
            engine_report_stream << std::string(50 - engine_report_stream.str().size(), '.');
            std::cout << engine_report_stream.str();

            std::string result = (verbose_output ? (engine_scan.Description) : (engine_scan.Detected ? "DIRTY" : "CLEAN"));

            if(result != "CLEAN") {
                SetConsoleTextAttribute(console_handle, FOREGROUND_RED | BACKGROUND_RED | BACKGROUND_BLUE | FOREGROUND_INTENSITY);
            } else {
                SetConsoleTextAttribute(console_handle, FOREGROUND_BLUE | BACKGROUND_BLUE | BACKGROUND_RED | FOREGROUND_INTENSITY);
            }

            std::cout << result;

            SetConsoleTextAttribute(console_handle, original_text_attributes);

            if(verbose_output) {
                std::cout << std::endl;
            } else {
                std::cout << ((i % 2) ? "\n" : " | ");
            }
        }

        std::cout << std::endl << std::string(virus_total_report.ReportLink.size(), '=') << std::endl << std::endl;
    } else {
        std::cout << "The response code is bad. Perhaps an error occured, or the file wasn't submitted yet." << std::endl;
        std::cout << "Response code: " << virus_total_report.ResponseCode << " | Message: " << (virus_total_report.ErrorMessage.empty() ? "None supplied." : virus_total_report.ErrorMessage) << std::endl;
    }

    return 0;
}
