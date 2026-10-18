#include "png.h"

int main(int argc, char **argv) {
    png_image writer = {0};
    png_image reader = {0};
    png_byte pixels[6] = {255, 80, 20, 10, 90, 240};
    png_byte encoded[2048];
    png_byte output[6];
    png_alloc_size_t length = sizeof encoded;
    int result;
    (void)argv;
    writer.version = PNG_IMAGE_VERSION;
    writer.width = 2;
    writer.height = 1;
    writer.format = PNG_FORMAT_RGB;
    result = png_image_write_to_memory(&writer, encoded, &length, 0, pixels, 0, NULL);
    reader.version = PNG_IMAGE_VERSION;
    if (result && png_image_begin_read_from_memory(&reader, encoded, length)) {
        reader.format = PNG_FORMAT_RGB;
        result = png_image_finish_read(&reader, NULL, output, 0, NULL);
    }
    png_image_free(&reader);
    png_image_free(&writer);
    return (int)png_access_version_number() - argc - result;
}
