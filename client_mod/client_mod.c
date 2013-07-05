#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include <l4/re/env.h>
#include <l4/sys/ipc.h>
//#include <l4/sys/__timeout.h>
//#include <l4/re/c/log.h>
#include "shared.h"
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static int decrypt(char*buf,int length);

static int encrypt(char*buf,int length);
#define SUCCESS 0
#define DEVICE_NAME "encrdev"
#define BUF_LEN 80
#define MAJOR 111
static int Device_Open = 0;
static char msg[BUF_LEN]; /*текст сообщения */


static struct file_operations fops = {
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release
};

int init_module(void)
{
  int retval = register_chrdev(MAJOR, DEVICE_NAME, &fops);
  return retval;
}

void cleanup_module(void)
{
  unregister_chrdev(MAJOR, DEVICE_NAME);
}


static int device_open(struct inode *inode, struct file *file)
{
	if (Device_Open)
		return -EBUSY;
	Device_Open++;
	try_module_get(THIS_MODULE);
	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file)
{
  Device_Open--;
  module_put(THIS_MODULE);
  return 0;
}

static ssize_t device_read(struct file *filp,
         char *buffer,
         size_t length,
         loff_t * offset)
{
	int bytes_read = 0;
	 char* tempbuf=(char*)kmalloc(BUF_LEN,GFP_KERNEL);
	 char *tempbuf_Ptr=0;
	if (*msg == 0)
		return 0;

	bytes_read =sprintf(tempbuf,msg);

	printk("Read: %s \n",tempbuf);
	if(decrypt(tempbuf,bytes_read)!=0)
	{
		printk("error call \n");	
		return 0;
	}
	printk("Decrypted: %s \n",tempbuf);
	tempbuf_Ptr=tempbuf;
	while (length && *tempbuf_Ptr)
	{
		put_user(*(tempbuf_Ptr++), buffer++);
		length--;
        }
	
	
	kfree(tempbuf);
	return bytes_read;
}

static ssize_t
device_write(struct file *file,
            const char __user * buffer, size_t length, loff_t * offset)
{
	int i;
	 char* tempbuf=(char*)kmalloc(BUF_LEN,GFP_KERNEL);

	for (i = 0; i<length && i < BUF_LEN; i++)
	{
		get_user(tempbuf[i], buffer + i);
	}
	printk("Write: %s \n",tempbuf);
	if(encrypt(tempbuf,length)!=0)
	{
		printk("error call \n");	
		return 0;
	}

	printk("Encrypted: %s \n",tempbuf);

	sprintf(msg, tempbuf);
	memcpy(msg, tempbuf,length);
	kfree(tempbuf);
	return i;
}

static int decrypt(char*buf,int length)
{

	l4re_env_t * env=l4re_env();
	l4_cap_idx_t server = l4re_env_get_cap("encr_server");
	if (l4_is_invalid_cap(server))
	{
		printk("invalid server cap");
		return 1;
	}	
	l4_msg_regs_t *mr=l4_utcb_mr();
	l4_msgtag_t tag,ret;
	int idx=0;
	mr->mr[idx++]=OPCODE_DECRYPT;
	mr->mr[idx++]=length;
	memcpy(&mr->mr[idx],buf,length);
	tag=l4_msgtag(PROTOCOL_ENCR,4+length/2+1,0,0);
	ret = l4_ipc_call(server, l4_utcb(),tag,L4_IPC_NEVER);
	memcpy(buf,&mr->mr[1],length);
	if (l4_error(ret))
		return 1; // failure
	return 0; // ok
}
static int encrypt(char*buf,int length)
{
	l4re_env_t * env=l4re_env();
	l4_cap_idx_t server = l4re_env_get_cap("encr_server");
	if (l4_is_invalid_cap(server))
	{
		printk("invalid server cap");
		return 1;
	}	
	l4_msg_regs_t *mr=l4_utcb_mr();
	l4_msgtag_t tag,ret;
	int idx=0;
	mr->mr[idx++]=OPCODE_ENCRYPT;
	mr->mr[idx++]=length;
	memcpy(&mr->mr[idx],buf,length);
	tag=l4_msgtag(PROTOCOL_ENCR,4+length/2+1,0,0);
	ret = l4_ipc_call(server, l4_utcb(),tag,L4_IPC_NEVER);
	memcpy(buf,&mr->mr[1],length);
	if (l4_error(ret))
		return 1; // failure
	return 0; // ok
}
