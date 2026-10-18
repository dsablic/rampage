#include "png.h"

int main(int argc, char **argv) {
    png_image image = {0};
    png_image decoded = {0};
    png_byte pixels[4] = {31, 63, 127, 255};
    png_byte encoded[1024];
    png_byte output[4];
    png_alloc_size_t size = sizeof encoded;
    int result;
    (void)argv;
    image.version = PNG_IMAGE_VERSION;
    image.width = 1;
    image.height = 1;
    image.format = PNG_FORMAT_RGBA;
    result = png_image_write_to_memory(&image, encoded, &size, 0, pixels, 0, NULL);
    decoded.version = PNG_IMAGE_VERSION;
    if (result && png_image_begin_read_from_memory(&decoded, encoded, size)) {
        decoded.format = PNG_FORMAT_RGBA;
        result = png_image_finish_read(&decoded, NULL, output, 0, NULL);
    }
    png_image_free(&decoded);
    png_image_free(&image);
    return result + (int)png_access_version_number() + argc;
}
