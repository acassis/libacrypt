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

#include "crypt.h"

/****************************************************************************
 * Preprocessor and Macros
 ****************************************************************************/

#define MAX_KEY_SIZE     256
#define MAX_INPUT_SIZE   1024 /* Max input size to allocate buffer */
#define MAX_OUTPUT_SIZE  1024 /* Max output size to allocate buffer */

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
  printf("Encrypt data from input file/stdin and save to output file/stdout\n\n");
  printf("Options:\n");
  printf("-h:               Show usage information on standard output\n");
  printf("-k <key>          Used to pass the algorithm key in the command line.\n");
  printf("-f <key_file>     Used to provide the algorithm key in a file.\n");
  printf("-o <output_file>  Write the results in <output_file>. Standard\n"
         "                  output shall be used if this parameter is not\n"
         "                  provided, or if <output_file> is a dash sign (-).\n");
  printf("-i <input_file>:  Read the input from <input_file>. Standard input\n"
         "                  shall be used if this parameter is not given.\n");
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
    }

  while ((c = getopt(argc, argv, ":hk:f:i:o:")) != -1)
    {
      switch(c)
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
 * @brief Open and load the content of a file.
 *
 * @param filename name of file to open
 * @param fd pointer user to save the opened file
 * @param buffer memory buffer pointer to save read bytes
 * @param maxsize maximum size to read from a file
 * @return Success (OK = 0) or a negative error
 */

static int load_file(char *filename, int *fd, char *buffer, int maxsize)
{
  int ret;

  *fd = open(filename, O_RDONLY);
  if (*fd < 0)
    {
      fprintf(stderr,
              "Error: failed to open file %s\n", filename);
      return -ENOENT;
    }

  /* Read the content of file to the buffer */

  ret = read(*fd, buffer, maxsize);
  if (ret < 0)
    {
      fprintf(stderr,
              "Error: failed to read file %s\n", filename);
      return -EAGAIN;
    }

  /* Save key size */

  return ret;
}

/**
 * @brief Open and save a buffer content to a file.
 *
 * @param args pointer to user args struct
 * @param buf memory buffer pointer with data to be written in the file
 * @return Success (OK = 0) or a negative error
 */

static int store_file(struct user_data_args_s *args, char *buf)
{
  int ret;

  /* Open or create file, replace previous content */

  args->fd_out = open(args->ofile, O_RDWR | O_TRUNC | O_CREAT);
  if (args->fd_out < 0)
    {
      fprintf(stderr,
              "Error: failed to open output file %s\n", args->ofile);
      return -EAGAIN;
    }

  ret = write(args->fd_out, buf, args->filelen);
  if (ret < 0)
    {
      fprintf(stderr,
              "Error: failed to write file, errno = %d\n", ret);
      return -EAGAIN;
    }

  return 0;
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

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * crypt main
 ****************************************************************************/

int main(int argc, char *argv[])
{
  int ret;
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
      args->keylen = load_file(args->kfile, &args->fd_key,
                               args->kbuf, MAX_KEY_SIZE);
      if (args->keylen < 0)
        {
          fprintf(stderr,
                  "Error: failed to load key file\n");
          free_close_alloc(args);
          return -EAGAIN;
        }
    }

  /* Should we load input from file? */

  if (args->ifile != NULL)
    {
      args->filelen = load_file(args->ifile, &args->fd_in,
                                args->ibuf, MAX_INPUT_SIZE);
      if (args->filelen < 0)
        {
          fprintf(stderr,
                  "Error: failed to load input file\n");
          free_close_alloc(args);
          return -EAGAIN;
        }
    }
  else
    {
      /* Input file not supplied, read from stdin */

      args->filelen = read_input(args->ibuf, MAX_INPUT_SIZE, args->ispipe);
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

  /* Encrypt the input buffer and save it on output buffer */

  ret = crypt_buffer(context, args->obuf, args->ibuf, args->filelen);
  if (ret < 0)
    {
      fprintf(stderr,
              "Error: failed to encrypt file, errno = %d\n", ret);
      free_close_alloc(args);
      return -EAGAIN;
    }

  /* Should we store the output in a file? */

  if (args->ofile != NULL)
    {
      ret = store_file(args, args->obuf);
      if (ret < 0)
        {
          free_close_alloc(args);
          return -EAGAIN;
        }
    }
  else
    {
      /* No, write it to the stdout */

      ret = write(1, args->obuf, args->filelen);
      if (ret < 0)
        {
          fprintf(stderr, "Error: failed to write to stdout = %d\n", ret);
          free_close_alloc(args);
          return -EAGAIN;
        }
    }

  return 0;
}

