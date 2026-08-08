#ifndef GLUTTON_SPICY_BRIDGE_H
#define GLUTTON_SPICY_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char* name;         // name of field
    char* value;        // value of field.
    int is_binary;      // flag (0 or 1) indicating if value is raw bytes
    int length;         // length of value, essential for binary data
} ParsedField;

typedef struct {
    ParsedField* fields;
    int field_count;
    int capacity;
    char* protocol_name;
    char* error_message;
} ParsedData;

/**
 * @brief Initializes the Spicy and HILTI runtimes.
 */
void spicy_init();

/**
 * @brief Checks if the Spicy runtime is initialized.
 * returns 1 if initialized, 0 if not.
 */
int spicy_is_initialized();

/**
 * @brief Cleans up and shuts down the Spicy and HILTI runtimes.
 */
void spicy_cleanup();

/**
 * @brief Lists all available (compiled-in) Spicy parsers.
 */
char** spicy_list_parsers(int* count);

/**
 * @brief The main generic parsing function.
 */
ParsedData* spicy_parse_generic(const char* parser_name, const unsigned char* data, int length);

/**
 * @brief Frees the memory allocated for a ParsedData struct.
 */
void spicy_free_parsed_data(ParsedData* data);

/**
 * @brief Frees the memory allocated for the parser list returned by spicy_list_parsers.
 */
void spicy_free_parser_list(char** parsers, int count);

#ifdef __cplusplus
}
#endif

#endif // GLUTTON_SPICY_BRIDGE_H