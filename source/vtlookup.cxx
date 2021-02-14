#include <source/vtlookup.hxx>

using VTERROR = VirusTotalReport::VTERROR;

std::size_t VirusTotalReport::curlWriter(void *data, std::size_t fake_size, std::size_t size, std::string *out_string) {
    out_string->append(reinterpret_cast<char*>(data), fake_size * size);
    return fake_size * size;
}

VTERROR VirusTotalReport::getRequest(const std::string& url, HttpResponse* out_response) {
    CURL* curl_session = curl_easy_init();

    if(curl_session) {
        // The HttpResponse instance that will store the response data for this request.
        HttpResponse http_response;

        // Configure the curl session handle.
        curl_easy_setopt(curl_session, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_session, CURLOPT_USERAGENT, "curl");
        curl_easy_setopt(curl_session, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl_session, CURLOPT_WRITEFUNCTION, &curlWriter);
        curl_easy_setopt(curl_session, CURLOPT_WRITEDATA, &http_response.Body);
        curl_easy_setopt(curl_session, CURLOPT_HEADERDATA, &http_response.Header);
        curl_easy_setopt(curl_session, CURLOPT_TCP_KEEPALIVE, 2UL);

        #ifdef DEBUG
        curl_easy_setopt(curl_session, CURLOPT_VERBOSE, 1L);
        #endif

        // Perform the HTTP/GET request configured in the current curl session handle.
        curl_easy_perform(curl_session);

        /* Get the HTTP status code given by the server when performing the request.
         * This can be 0 if no code was given by the server, which could indicate
         * that a connection couldn't be established to the server. */
        curl_easy_getinfo(curl_session, CURLINFO_HTTP_CODE, &http_response.StatusCode);

        // If out_response isn't nullptr, write a copy of http_response to out_response.
        if(out_response != nullptr) *out_response = http_response;

        // Cleanup / release the curl session handle.
        curl_easy_cleanup(curl_session);
        curl_session = nullptr;

        return VTERROR::ERRORLESS;
    } else {
        return VTERROR::INVALID_CURL_HANDLE;
    }
}

VTERROR VirusTotalReport::DownloadReport(const std::string& resource, HttpResponse* out_response) {
    // Use a stringstream to construct the API request URL.
    std::stringstream request_url_stream;
    request_url_stream << "https://www.virustotal.com/vtapi/v2/file/report";
    request_url_stream << "?apikey=" << ApiKey;
    request_url_stream << "&resource=" << resource;

    // Get the constructed API request URL from the stringstream.
    const std::string request_url = request_url_stream.str();
    request_url_stream.clear(); // Clear the stringstream as its memory is now useless.

    return getRequest(request_url, out_response);
}

VTERROR VirusTotalReport::DownloadReport(const std::string& resource, Json* out_json, HttpResponse* out_response) {
    HttpResponse http_response;
    Json json_parsed_body;

    VTERROR error_code = DownloadReport(resource, &http_response);

    if(out_json != nullptr) *out_json = json_parsed_body;
    if(out_response != nullptr) *out_response = http_response;

    if(error_code == VTERROR::ERRORLESS) {
        try {
            json_parsed_body = Json::parse(http_response.Body);
        } catch(const nlohmann::detail::exception&) {
            return VTERROR::PARSING_ERROR;
        }
    }

    return error_code;
}

VTERROR VirusTotalReport::LoadReport(const Json& json_report) {
    ResetReportData(); // Clear the report variables to ensure that no old data is present in the new report.

    /* These two maps are used to resolve where a value from a JSON key/value pair
     * should go, by mapping its key which will always be a string, to a pointer
     * of a member variable of the matching value type. The value data will then be
     * written to the variable that the matching pointer points to.
     * */
    std::map<std::string, std::string*> string_value_map {
        {"verbose_msg", &(this->ErrorMessage)},
        {"permalink", &(this->ReportLink)},
        {"scan_date", &(this->ScanDate)},
        {"resource", &(this->Resource)},
        {"sha256", &(this->FileSha256Hexdigest)},
        {"sha1", &(this->FileSha1Hexdigest)},
        {"md5", &(this->FileMd5Hexdigest)},
    };

    std::map<std::string, int32_t*> integer_value_map {
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
            *integer_value_map.at(kvpair.key()) = kvpair.value().get<int32_t>();
        }

        // Parses the "scans" structure in the report, and constructs a new EngineScan object for
        // every scan, before emplacing it into the EngineScans vector member variable.
        else if(kvpair.key() == "scans" && kvpair.value().is_structured()) {
            const auto& engine_scans_json_object = kvpair.value();

            for(const auto& engine_scan_kvpair : engine_scans_json_object.items()) {
                const auto& engine_scan_values = engine_scan_kvpair.value();

                // Use the values within engine_scan_values to construct a new EngineScan object.
                EngineScan engine_scan_object {
                   // Yield the engine's version number if the "version" key is present and its value is a string, otherwise yield "NONE GIVEN".
                   (engine_scan_values.find("version") != engine_scan_values.end() && engine_scan_values.at("version").is_string())
                        ? engine_scan_values.at("version").get<std::string>()
                        : "NONE GIVEN",

                    /* If the "result" key isn't there yield "NONE GIVEN", otherwise yield the "result" key's value,
                     * unless the value isn't a string, in which case yield "CLEAN".
                     * */
                   (engine_scan_values.find("result") != engine_scan_values.end())
                        ? ((!engine_scan_values.at("result").is_string())
                            ? "CLEAN"
                            : engine_scan_values.at("result").get<std::string>())
                        : "NONE GIVEN",

                   // The key name of the the engine scan structure is the name of the AV engine.
                   engine_scan_kvpair.key(),

                   // Yield the "update" key's value if the key is present, and the value is a string, otherwise yield "NONE GIVEN".
                   (engine_scan_values.find("update") != engine_scan_values.end() && engine_scan_values.at("update").is_string())
                        ? engine_scan_values.at("update").get<std::string>()
                        : "NONE GIVEN",

                    // Yield the "detected" key's value if the key is present, and the value is a bool, otherwise yield false.
                   (engine_scan_values.find("detected") != engine_scan_values.end() && engine_scan_values.at("detected").is_boolean())
                        ? engine_scan_values.at("detected").get<bool>()
                        : false
                };

                // Emplace the new EngineScan object to the vector of EngineScan objects.
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

    return VTERROR::ERRORLESS;
}

VTERROR VirusTotalReport::LoadReport(const std::string& raw_report) {
    try {
        Json json_report = Json::parse(raw_report);
        return LoadReport(json_report);
    } catch(const nlohmann::detail::exception&) {
        return VTERROR::PARSING_ERROR;
    }
}

std::pair<VTERROR, VTERROR> VirusTotalReport::DownloadAndLoadReport(const std::string& resource, Json* out_json, HttpResponse* out_response) {
    Json downloaded_json_report;
    HttpResponse http_response;

    VTERROR dl_error_code = DownloadReport(resource, &downloaded_json_report, &http_response);

    if(out_json != nullptr) *out_json = downloaded_json_report;
    if(out_response != nullptr) *out_response = http_response;

    if(dl_error_code == VTERROR::ERRORLESS) {
        VTERROR ld_error_code = LoadReport(downloaded_json_report);
        return std::make_pair(dl_error_code, ld_error_code);
    } else {
        return std::make_pair(dl_error_code, VTERROR::UNASSIGNED);
    }
}

VTERROR VirusTotalReport::SubmitFile(const std::string& file_path, HttpResponse* out_response) {
    std::stringstream request_url_stream;
    request_url_stream << "https://www.virustotal.com/vtapi/v2/file/scan";
    request_url_stream << "?apikey=" << ApiKey;

    const std::string request_url = request_url_stream.str();
    request_url_stream.clear();

    CURL* curl_session = curl_easy_init();

    if(curl_session) {
        HttpResponse http_response;

        #ifdef DEBUG
        curl_easy_setopt(curl_session, CURLOPT_VERBOSE, 1L);
        #endif

        curl_easy_setopt(curl_session, CURLOPT_URL, request_url.c_str());
        curl_easy_setopt(curl_session, CURLOPT_POST, 1L);
        curl_easy_setopt(curl_session, CURLOPT_WRITEDATA, &http_response.Body);
        curl_easy_setopt(curl_session, CURLOPT_WRITEFUNCTION, &curlWriter);
        curl_easy_setopt(curl_session, CURLOPT_HEADERDATA, &http_response.Header);

        struct curl_httppost* form_data = nullptr;
        struct curl_httppost* last_form_data = nullptr;


        curl_formadd(&form_data, &last_form_data, CURLFORM_COPYNAME, "file", CURLFORM_FILE, file_path.c_str(), CURLFORM_END);
        curl_easy_setopt(curl_session, CURLOPT_HTTPPOST, form_data);

        curl_easy_perform(curl_session);

        curl_easy_getinfo(curl_session, CURLINFO_HTTP_CODE, &http_response.StatusCode);
        if(out_response != nullptr) *out_response = http_response;

        curl_easy_cleanup(curl_session);

        return VTERROR::ERRORLESS;
    } else {
        return VTERROR::INVALID_CURL_HANDLE;
    }
}

VTERROR VirusTotalReport::SubmitFile(const std::string& file_path, Json* out_json, HttpResponse* out_response) {
    HttpResponse http_response;
    Json response_body_json;

    VTERROR error_code = SubmitFile(file_path, &http_response);

    if(error_code == VTERROR::ERRORLESS) {
        try {
            response_body_json = Json::parse(http_response.Body);
        } catch(const nlohmann::detail::exception&) {
            return VTERROR::PARSING_ERROR;
        }

        if(out_response != nullptr) *out_response = http_response;
        if(out_json != nullptr) *out_json = response_body_json;
    }

    return error_code;
}

void VirusTotalReport::ResetReportData() {
    EngineScans.clear();

    ResponseCode    =   0x7FFFFFFF;
    Positives       =   0x7FFFFFFF;
    Negatives       =   0x7FFFFFFF;
    ScanCount       =   0x7FFFFFFF;
    DetectionRatio  =   -1;

    FileSha256Hexdigest.clear();
    FileSha1Hexdigest.clear();
    ErrorMessage.clear();
    ReportLink.clear();
    Resource.clear();
    ScanDate.clear();
    ScanId.clear();
}

void VirusTotalReport::RenderReport(bool verbose) const {
    // Helper lambda that simplifies changing the text color of certain report elements.
    static const std::function<void(uint16_t)>& set_color = [](uint16_t color = NULL) {
        static HANDLE console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        static uint16_t original_color = NULL;

        if(original_color == NULL) {
            CONSOLE_SCREEN_BUFFER_INFO console_screen_buffer_info;
            GetConsoleScreenBufferInfo(console_handle, &console_screen_buffer_info);
            original_color = console_screen_buffer_info.wAttributes;
        }

        SetConsoleTextAttribute(console_handle, color == NULL ? original_color : color);
    };

    if(verbose) {
        const std::function<std::size_t(const EngineScan& engine_scan)>& get_enginescan_length = [](const EngineScan& engine_scan) -> std::size_t {
            return engine_scan.EngineName.size() + engine_scan.EngineVersion.size() + 2 + (engine_scan.Detected ? engine_scan.Description.size() : 5);
        };

        // Finds the EngineScan instance in the EngineScans vector who's description and version is biggest, used as a base padding value.
        const EngineScan& largest_scan_string = *std::max_element(EngineScans.begin(), EngineScans.end(), [&get_enginescan_length](const EngineScan& scan1, const EngineScan& scan2) -> bool {
            return get_enginescan_length(scan1) < get_enginescan_length(scan2);
        });

        const std::size_t& base_padding = get_enginescan_length(largest_scan_string);

        std::cout << std::string((base_padding * 2) + 23, '-') << std::endl;

        for(std::size_t i=0; i<EngineScans.size(); ++i) {
            const EngineScan& engine_scan = EngineScans.at(i);

            set_color((engine_scan.Detected ? FOREGROUND_RED : FOREGROUND_GREEN) | FOREGROUND_INTENSITY);
            std::cout << engine_scan.EngineName << "(" << engine_scan.EngineVersion << ")";
            std::cout << std::string(base_padding - get_enginescan_length(engine_scan) + 10, '.');
            std::cout << (engine_scan.Detected ? engine_scan.Description : "CLEAN");
            set_color(NULL);

            std::cout << (!(i % 2) ? ((i+1) < EngineScans.size() ? " | " : " |\n") : "\n");
        }

        std::cout << std::string((base_padding * 2) + 23, '-') << std::endl;
    } else {
        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "REPORT FOUND ~> ";

        set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << Positives;

        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " / ";

        set_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << ScanCount;

        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " [ " << DetectionRatio << "%] @ " << ScanDate << " | ";

        set_color(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << Positives << " positives";

        set_color(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << " & " << Negatives << " negatives, out of ";

        set_color(FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << ScanCount << " distinct AV engine scans.." << std::endl;
        
        set_color(NULL);
    }
}

VirusTotalReport::VirusTotalReport(const std::string& api_key) {
    ApiKey = api_key;
    ResetReportData();
}

VirusTotalReport::~VirusTotalReport() {
    ResetReportData();
}
