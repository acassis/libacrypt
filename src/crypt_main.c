/****************************************************************************
 * @file  src/crypt_main.c
 *
 * @brief Command line crypt program.
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <limits.h>

#include "acrypt.h"

/****************************************************************************
 * Preprocessor and Macros
 ****************************************************************************/

#define MAX_KEY_SIZE     256
#define MAX_INPUT_SIZE   1024 /* Max input size to allocate buffer */
#define MAX_OUTPUT_SIZE  1024 /* Max output size to allocate buffer */
#define MAX_READ_RETRY   15   /* Case read() fails, retry X times */

/****************************************************************************
 * Private Types
 ****************************************************************************/

/** @struct user_data_args_s
 *  @brief This structure saves data supplied by user
 *  @var user_data_args_s::fd_in
 *  Member 'fd_in' is file descriptor of input file
 *  @var user_data_args_s::fd_key
 *  Member 'fd_key' is file descriptor of key file
 *  @var user_data_args_s::fd_out
 *  Member 'fd_out' is file descriptor of output file
 *  @var user_data_args_s::filelen
 *  Member 'filelen' contains the size of input file
 *  @var user_data_args_s::keylen
 *  Member 'keylen' contains the size of key file
 *  @var user_data_args_s::kfile
 *  Member 'kfile' pointer to key file name
 *  @var user_data_args_s::ifile
 *  Member 'ifile' pointer to input file name
 *  @var user_data_args_s::ofile
 *  Member 'ofile' pointer to output file name
 *  @var user_data_args_s::kbuf
 *  Member 'kbuf' pointer to key buffer
 *  @var user_data_args_s::ibuf
 *  Member 'ibuf' pointer to input buffer
 *  @var user_data_args_s::obuf
 *  Member 'obuf' pointer to output buffer
 */

struct user_data_args_s
{
  int fd_in;       /* file descriptor to the user input file  */
  int fd_key;      /* file descriptor to the user key file    */
  int fd_out;      /* file descriptor to the user output file */
  int filelen;     /* size of input file                      */
  int keylen;      /* size of key file                        */
  bool ispipe;     /* parameter '-' passed, assume pipe stdin */
  char *kfile;     /* pointer to user supplied key file       */
  char *ifile;     /* pointer to user supplied input file     */
  char *ofile;     /* pointer to user supplied output file    */
  char *kbuf;      /* pointer to user key buffer              */
  char *ibuf;      /* pointer to user input buffer            */
  char *obuf;      /* pointer to user output buffer           */
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/**
 *  @brief Show the command options to help the user to use the program.
 */

static void show_help(void)
{
  printf("Usage:\n");
  printf("crypt [-h] -k <key> | -f <key_file>"
         " [-o <output_file>] [<input_file>]\n\n");
  printf("Encrypt data from input file/stdin and save to file/stdout\n\n");
  printf("Options:\n");
  printf("-h:               Show usage information on standard output\n");
  printf("-k <key>          Used to pass the algo key in the cmd line.\n");
  printf("-f <key_file>     Used to provide the algorithm key in a file.\n");
  printf("-o <output_file>  Write the results in <output_file>. Standard\n"
         "                  output shall be used if this parameter is not\n"
         "                  provided, or if it is a dash sign (-).\n");
  printf("-i <input_file>:  Read the input from <input_file>. Stand input\n"
         "                  shall be used if this param is not given.\n");
}

/**
 * @brief Parse user supplied arguments from command line.
 *
 * @param args pointer to struct with user arguments variable
 * @param argc amount to arguments read from command line
 * @param argv command line arguments
 */

static void parse_args(struct user_data_args_s *args,
                       int argc, char **argv)
{
  int c;

  /* Is there a dash to indicate | read from stdin? */

  if (strcmp(argv[argc - 1], "-") == 0)
    {
      args->ispipe = true;
      args->ifile = strdup("stdin");
    }

  while ((c = getopt(argc, argv, ":hk:f:i:o:")) != -1)
    {
      switch (c)
      {
        case 'h':
            show_help();
            break;
        case 'k':
            strcpy(args->kbuf, optarg);
            args->keylen = strlen(args->kbuf);
            break;
        case 'f':
            args->kfile = strdup(optarg);
            break;
        case 'i':
            args->ifile = strdup(optarg);
            break;
        case 'o':
            args->ofile = strdup(optarg);
            break;
        case ':':       /* -k or -f without operand */
            fprintf(stderr,
                "Option -%c requires an operand\n", optopt);
            break;
        case '?':
            fprintf(stderr,
                "Unrecognized option: '-%c'\n", optopt);
      }
    }
}

/**
 * @brief Initialize and Allocate memory to user arguments
 *
 * @param args pointer to user args struct
 * @return Success (OK = 0) or a negative error
 */

static int init_alloc_args(struct user_data_args_s *args)
{
  /* Initialize args variables */

  args->filelen = 0;
  args->keylen  = 0;
  args->kfile   = NULL;
  args->ifile   = NULL;
  args->ofile   = NULL;
  args->fd_in   = -1;
  args->fd_key  = -1;
  args->fd_out  = -1;
  args->ispipe  = false;

  args->kbuf = malloc(MAX_KEY_SIZE + 1);
  if (args->kbuf == NULL)
    {
      return -ENOMEM;
    }

  args->ibuf = malloc(MAX_INPUT_SIZE);
  if (args->ibuf == NULL)
    {
      return -ENOMEM;
    }

  args->obuf = malloc(MAX_OUTPUT_SIZE);
  if (args->obuf == NULL)
    {
      return -ENOMEM;
    }

  return 0;
}

/**
 * @brief Free memory and Close files from user arguments
 *
 * @param args pointer to user args struct
 */

void free_close_alloc(struct user_data_args_s *args)
{
  if (args->kfile != NULL)
    {
      free(args->kfile);
    }

  if (args->ifile != NULL)
    {
      free(args->ifile);
    }

  if (args->ofile != NULL)
    {
      free(args->ofile);
    }

  if (args->kbuf != NULL)
    {
      free(args->kbuf);
    }

  if (args->ibuf != NULL)
    {
      free(args->ibuf);
    }

  if (args->obuf != NULL)
    {
      free(args->obuf);
    }

  if (args->fd_in != -1)
    {
      close(args->fd_in);
    }

  if (args->fd_out != -1)
    {
      close(args->fd_out);
    }

  if (args->fd_key != -1)
    {
      close(args->fd_key);
    }
}

/**
 * @brief Read typed characters and store in a buffer
 *
 * @param args pointer to user args struct
 * @param buf memory buffer pointer to store read chars
 * @param maxsize maximum size to read from a file
 * @return Amount of read characters
 */

static int read_input(char *buf, int maxsize, bool pipe)
{
  int ch;
  int i = 0;

  /* Read input until EOF, if using stdin from pipe, don't print */

  if (!pipe)
    {
      printf("Type the text to be encrypted: ");
    }

  while ((ch = getchar()) != EOF)
    {
      /* If we got an Enter and it didn't come from "|" stop */

      if (ch == '\n' && !pipe)
        {
          break;
        }

      *buf++ = ch;
      i++;
      if (i >= maxsize)
        {
          break;
        }
    }

  /* Finish the string */

  buf = '\0';

  return i;
}

/**
 * @brief Open and read size of file, if stdin return MAX
 *
 * @param filename name of file to open
 * @param fd pointer user to save the opened file
 * @return Size of file or a negative error
 */

static int file_size(char *filename, int *fd)
{
  int ret;
  struct stat  sb;

  /* If file is "stdin" we don't open it as regular file */

  if (strcmp(filename, "stdin") == 0)
    {
      /* stdin is fd 0 */

      *fd = 0;

      /* Fake it is a big file */

      return INT_MAX;
    }

  *fd = open(filename, O_RDONLY);
  if (*fd < 0)
    {
      fprintf(stderr,
              "Error: failed to open file %s\n", filename);
      return -ENOENT;
    }

  /* To obtain file size */

  if (fstat(*fd, &sb) == -1)
    {
      fprintf(stderr,
              "Error: failed to fstat file %s\n", filename);
      return -ENOENT;
    }

  return sb.st_size;
}

/**
 * @brief Open and load the content of a file.
 *
 * @param filename name of file to open
 * @param fd pointer user to save the opened file
 * @param buffer memory buffer pointer to save read bytes
 * @param maxsize maximum size to read from a file
 * @return Success (OK = 0) or a negative error
 */

static int load_file(struct user_data_args_s *args, int fd,
                     char *buffer, int maxsize)
{
  int ret = 0;
  int retry = MAX_READ_RETRY;

  /* If it is stdin we need to read differently */

  if (fd == 0)
    {
      return read_input(buffer, maxsize, args->ispipe);
    }


  /* Read the content of file to the buffer
   * the read() function could return less
   * bytes than the requested, a simple workaround
   * is just try to read again.
   */

  while (ret != maxsize && retry > 0)
    {
      retry--;

      ret = read(fd, buffer, maxsize);
      if (retry == 0 && ret < 0)
        {
          fprintf(stderr,
                  "Error: failed to read file\n");
          return -EAGAIN;
        }
    }

  /* Return the amount of read bytes */

  return ret;
}

/**
 * @brief Open and save a buffer content to a file.
 *
 * @param args pointer to user args struct
 * @param buf memory buffer pointer with data to be written in the file
 * @return Success (OK = 0) or a negative error
 */

static int store_file(struct user_data_args_s *args, char *buf, int maxsize)
{
  int ret;

  /* Should we write to stdout or to file? */

  if (args->ofile == NULL)
    {
      /* write it to the stdout */

      ret = write(1, args->obuf, maxsize);
      if (ret < 0)
        {
          fprintf(stderr, "Error: failed to write to stdout = %d\n", ret);
          free_close_alloc(args);
          return -EAGAIN;
        }
    }
  else
    {
      /* Open or create file, replace previous content */

      if (args->fd_out == -1)
        {
          /* Disable file mask */

          umask(0);

          /* Open or Create it and remove previous content */

          args->fd_out = open(args->ofile, O_RDWR | O_TRUNC | O_CREAT, 0666);
          if (args->fd_out < 0)
            {
              fprintf(stderr,
                      "Error: failed to open output file %s\n", args->ofile);
              return -EAGAIN;
            }
        }

      ret = write(args->fd_out, buf, maxsize);
      if (ret < 0)
        {
          fprintf(stderr,
                  "Error: failed to write file, errno = %d\n", ret);
          return -EAGAIN;
        }
    }

  return 0;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * crypt main
 ****************************************************************************/

int main(int argc, char *argv[])
{
  int ret;
  int remaining;
  struct crypt_context *context;  /* struct context to save info  */
  struct user_data_args_s *args;  /* struct to store user args    */

  /* Allocate the struct to save user supplied arguments */

  args = malloc(sizeof(struct user_data_args_s));
  if (args == NULL)
    {
      fprintf(stderr, "Error: failed to allocate user arguments\n");
      return -ENOMEM;
    }

  /* Initialize and allocate user argument variables */

  ret = init_alloc_args(args);
  if (ret < 0)
    {
      free_close_alloc(args);
      return -EAGAIN;
    }

  /* Parse user supplied arguments */

  parse_args(args, argc, argv);

  /* Verify if user provided the key or key file */

  if (args->keylen == 0 & args->kfile == NULL)
    {
      fprintf(stderr, "Error: key wasn't supplied!\n");
      return -EINVAL;
    }

  /* Should we load key from file? */

  if (args->kfile != NULL)
    {
      int nread;

      /* Open and get the size of key file */

      args->keylen = file_size(args->kfile, &args->fd_key);
      if (args->keylen < 0)
        {
          fprintf(stderr,
                  "Error: failed to open and stat key file\n");
          free_close_alloc(args);
          return -EAGAIN;
        }

      /* Load the entire key file (since it is only up to 256 bytes) */

      nread = load_file(args, args->fd_key, args->kbuf, args->keylen);
      if (nread < 0)
        {
          fprintf(stderr,
                  "Error: failed to load key file\n");
          free_close_alloc(args);
          return -EAGAIN;
        }
    }

  /* Create context to save the key */

  context = malloc(sizeof(struct crypt_context));
  if (context == NULL)
    {
      fprintf(stderr, "Error: failed to allocate context struct\n");
      free_close_alloc(args);
      return -EAGAIN;
    }

  /* Save key buffer pointer and length to context */

  context->key = args->kbuf;
  context->keylen = args->keylen;

  /* If your didn't supply input file, read from stdin */

  if (args->ifile == NULL)
    {
      args->ifile = strdup("stdin");
    }

  /* Open the input file and get its size */

  args->filelen = file_size(args->ifile, &args->fd_in);
  if (args->filelen < 0)
    {
      fprintf(stderr,
              "Error: failed to open and stat input file\n");
      free_close_alloc(args);
      return -EAGAIN;
    }

  /* Read and process blocks of data until end of file */

  remaining = args->filelen;
  while (remaining > 0)
    {
      int nread;
      int blocks_read;

      blocks_read = remaining > MAX_INPUT_SIZE ? MAX_INPUT_SIZE : remaining;

      nread = load_file(args, args->fd_in, args->ibuf, blocks_read);
      if (nread < blocks_read && args->fd_in != 0) /* stdin can return less */
        {
          fprintf(stderr,
                  "Error: load_file() returned less bytes than expected!\n");
          free_close_alloc(args);
          return -EAGAIN;
        }

      remaining -= blocks_read;

      /* Encrypt the input buffer and save it on output buffer */

      ret = crypt_buffer(context, args->obuf, args->ibuf, nread);
      if (ret < 0)
        {
          fprintf(stderr,
                  "Error: failed to encrypt file, errno = %d\n", ret);
          free_close_alloc(args);
          return -EAGAIN;
        }

      /* Should we store the output in a file? */

      ret = store_file(args, args->obuf, nread);
      if (ret < 0)
        {
          free_close_alloc(args);
          return -EAGAIN;
        }

      /* If stdin returned less than MAX_INPUT_SIZE, then we are done */

      if (args->fd_in == 0 && nread < MAX_INPUT_SIZE)
        {
          break;
        }
    }

  return 0;
}

