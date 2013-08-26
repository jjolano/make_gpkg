#include <string>
#include <vector>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/sha.h>

#include "bytes.h"
#include "pkg.h"

using namespace std;

extern "C" {
	void keyToContext(uint8_t key[0x10], uint8_t largekey[0x40]);
	void setContextNum(uint8_t largekey[0x40]);
	void manipulate(uint8_t key[0x40]);
	void pkg_crypt(uint8_t largekey[0x40], uint8_t* input, int length);
}

int hexstr(char* dst, uint8_t* hex, const uint32_t hexlen)
{
	int len = 0;
	uint32_t i;

	for(i = 0; i < hexlen; i++)
	{
		len += sprintf(dst+len, "%02X", hex[i]);
	}

	return len;
}

void prepare_file_data(string prefix, string pkg_directory, vector<gpkg_file>* pkg_files, vector<string>* file_paths)
{
	DIR* dirp = opendir(pkg_directory.c_str());

	if(dirp == NULL)
	{
		perror("error");
		return;
	}

	struct dirent* dp;
	struct stat stbuf;

	char* path = new char[1024];
	memset(path, 0, 1024);

	while((dp = readdir(dirp)) != NULL)
	{
		// skip hidden files
		if(dp->d_name[0] == '.')
		{
			// skip
			continue;
		}

		snprintf(path, 1023, "%s/%s", pkg_directory.c_str(), dp->d_name);

		if(stat(path, &stbuf) == -1)
		{
			perror(path);
			continue;
		}

		string file_name(prefix);
		file_name += dp->d_name;

		int name_len = file_name.size();
		uint64_t file_size = stbuf.st_size;

		gpkg_file pkg_file = {};

		pkg_file.flags = PKG_FILE_OVERWRITE;
		pkg_file.filename_size = _ES32(name_len);

		file_paths->push_back(file_name);

		if((stbuf.st_mode & S_IFMT) == S_IFDIR)
		{
			// directory
			pkg_file.flags |= PKG_FILE_DIRECTORY;
			printf(" directory: %s\n", file_name.c_str());

			// add
			pkg_file.flags = _ES32(pkg_file.flags);
			pkg_files->push_back(pkg_file);

			// recurse
			prepare_file_data(file_name + "/", path, pkg_files, file_paths);
		}
		else
		{
			// file
			pkg_file.flags |= PKG_FILE_RAW;
			pkg_file.data_size = _ES64(file_size);
			printf("  raw data: %s\n", file_name.c_str());

			// add
			pkg_file.flags = _ES32(pkg_file.flags);
			pkg_files->push_back(pkg_file);
		}
	}

	delete [] path;
	closedir(dirp);
}

int main(int argc, char* argv[])
{
	printf("make_gpkg v0.1 by jjolano\n");

	if(argc < 4)
	{
		printf("usage: %s <contentid> <pkg-directory> <target-pkg>\n", argv[0]);
		return 1;
	}

	if(strlen(argv[1]) != 36)
	{
		fprintf(stderr, "error: contentid must be 36 characters\n");
		return 1;
	}
	
	// structs
	gpkg_header header = {};
	gpkg_crypt header_crypt = {};
	gpkg_info pkg_info = {};
	gpkg_einfo pkg_einfo = {};
	gpkg_crypt pkg_info_crypt = {};
	gpkg_footer footer = {};

	// gpkg_header constants
	header.magic = _ES32(0x7f504b47);
	header.pkg_type = _ES32(0x1);
	header.pkg_info_offset = _ES32(sizeof(gpkg_header) + sizeof(gpkg_crypt));
	header.pkg_info_size = _ES32(sizeof(gpkg_info) / 8);
	header.header_size = _ES32(sizeof(gpkg_header) + sizeof(gpkg_crypt));
	header.data_offset = _ES64(sizeof(gpkg_header) + sizeof(gpkg_crypt) + sizeof(gpkg_info) + sizeof(gpkg_einfo) + sizeof(gpkg_crypt));
	strncpy(header.contentid, argv[1], sizeof(header.contentid));

	// welcome to the world of unknown

	// gpkg_info constants
	pkg_info.unknown11 = _ES32(0x1);
	pkg_info.unknown12 = _ES32(0x4);
	pkg_info.drm_type = _ES32(0x3); // free
	pkg_info.unknown14 = _ES32(0x2);
	pkg_info.unknown21 = _ES32(0x4);
	pkg_info.unknown22 = _ES32(0x5); // gameexec
	pkg_info.unknown23 = _ES32(0x3);
	pkg_info.unknown24 = _ES32(0x4);
	pkg_info.unknown31 = _ES32(0x4e); // gameexec
	pkg_info.unknown32 = _ES32(0x4);
	pkg_info.unknown33 = _ES32(0x8);
	pkg_info.secondary_version = _ES16(0x0);
	pkg_info.unknown34 = _ES16(0x0);
	pkg_info.unknown42 = _ES32(0x5);
	pkg_info.unknown43 = _ES32(0x4);
	pkg_info.pkg_author = _ES16(0x1732); // make_package_npdrm revision
	pkg_info.pkg_version = _ES16(0x0100); // package.conf PACKAGE_VERSION

	// gpkg_einfo constants
	pkg_einfo.unknown11 = _ES32(0x7);
	pkg_einfo.unknown12 = _ES32(0x18);
	pkg_einfo.unknown13 = _ES32(0x0);
	pkg_einfo.unknown14 = _ES32(0x0);
	pkg_einfo.unknown31 = _ES32(0x8);
	pkg_einfo.unknown32 = _ES32(0x8);
	pkg_einfo.pkg_flags = 0x85;
	pkg_einfo.fw_major = 0x3;
	pkg_einfo.fw_minor = _ES16(0x4000);
	pkg_einfo.pkg_version = _ES16(0x0100);
	pkg_einfo.app_version = _ES16(0x0100);
	pkg_einfo.unknown41 = _ES32(0x9);
	pkg_einfo.unknown42 = _ES32(0x8);
	pkg_einfo.unknown43 = _ES32(0x0);
	pkg_einfo.unknown44 = _ES32(0x0);

	// process pkg directory
	printf("Packing file data ...\n");

	vector<gpkg_file> pkg_files;
	vector<string> file_paths;
	gpkg_crypt pkg_data_crypt = {};
	uint8_t* pkg_data;

	prepare_file_data("", argv[2], &pkg_files, &file_paths);

	header.item_count = pkg_files.size();

	uint64_t base_offset = sizeof(gpkg_file) * header.item_count;
	uint32_t filename_offset = 0;
	uint64_t data_offset = 0;

	for(vector<gpkg_file>::iterator it = pkg_files.begin(); it != pkg_files.end(); it++)
	{
		header.data_size += sizeof(gpkg_file) + ALIGN(_ES64(it->data_size), 0x10);

		it->filename_offset = _ES32(base_offset + filename_offset);
		filename_offset += ALIGN(_ES32(it->filename_size), 0x10);
	}

	header.data_size += filename_offset;
	base_offset += filename_offset;

	for(vector<gpkg_file>::iterator it = pkg_files.begin(); it != pkg_files.end(); it++)
	{
		it->data_offset = _ES64(base_offset + data_offset);
		data_offset += ALIGN(_ES64(it->data_size), 0x10);
	}

	base_offset -= filename_offset;

	pkg_data = new uint8_t[header.data_size];
	memset(pkg_data, 0, header.data_size);

	memcpy(pkg_data, &pkg_files.front(), sizeof(gpkg_file) * header.item_count);

	uint32_t i;
	for(i = 0; i < header.item_count; i++)
	{
		uint32_t filename_size = _ES32(pkg_files.at(i).filename_size);
		uint32_t filename_size_align = ALIGN(filename_size, 0x10);

		memcpy(pkg_data + base_offset, file_paths.at(i).c_str(), filename_size);

		base_offset += filename_size_align;
	}

	data_offset = 0;

	char* path = new char[1024];

	for(vector<string>::iterator ti = file_paths.begin(); ti != file_paths.end(); ti++)
	{
		snprintf(path, 1023, "%s/%s", argv[2], ti->c_str());

		struct stat stbuf;

		if(stat(path, &stbuf) == -1)
		{
			perror(path);
			continue;
		}

		if((stbuf.st_mode & S_IFMT) == S_IFDIR)
		{
			//data_offset += 0x10;
			continue;
		}

		FILE* filep = fopen(path, "rb");

		if(filep == NULL)
		{
			perror(path);
			return 1;
		}

		fseek(filep, 0, SEEK_END);
		uint64_t nlen = ftell(filep);
		fseek(filep, 0, SEEK_SET);

		uint8_t* data = new uint8_t[nlen];
		fread(data, 1, nlen, filep);

		uint64_t data_size_align = ALIGN(nlen, 0x10);
		memcpy(pkg_data + base_offset + data_offset, data, nlen);
		data_offset += data_size_align;

		fclose(filep);
		delete [] data;
	}

	delete [] path;

	// fix to minimum 100 KB
	uint8_t* size_fix = NULL;
	uint64_t pad_size = 0;

	header.total_size = _ES64(header.data_offset) + header.data_size + sizeof(gpkg_crypt) + sizeof(gpkg_footer);

	if(header.total_size < 102400)
	{
		pad_size = 102400 - header.total_size;
		printf("Fixing pkg size to 100 KB ...\n");
		size_fix = new uint8_t[pad_size];
		memset(size_fix, 0, pad_size);
		header.total_size += pad_size;
	}

	// calculate new offsets and sizes
	printf("Calculating offsets ...\n");

	header.data_size = _ES64(header.data_size);
	header.item_count = _ES32(header.item_count);
	header.total_size = _ES64(header.total_size);

	pkg_info.data_size = _ES32(_ES64(header.data_size));

	// print some pkg info
	printf(" PKG item count: %d (%#x)\n", _ES32(header.item_count), _ES32(header.item_count));
	printf(" PKG data offset: %llu (%#llx)\n", _ES64(header.data_offset), _ES64(header.data_offset));
	printf(" PKG data size: %llu (%#llx)\n", _ES64(header.data_size), _ES64(header.data_size));
	printf(" PKG total size: %llu (%#llx)\n", _ES64(header.total_size), _ES64(header.total_size));

	// calculate hashes
	printf("Calculating hashes ...\n");

	//uint8_t md[MD5_DIGEST_LENGTH] = {0x0f, 0xfa, 0x20, 0x55, 0x54, 0xb5, 0x6b, 0xe8, 0xa0, 0x0e, 0xf8, 0x79, 0x73, 0x67, 0xae, 0x7b};

	uint8_t sha[SHA_DIGEST_LENGTH];
	SHA_CTX ctx_sha1;

	SHA1(pkg_data, _ES64(header.data_size), sha);
	memcpy(header.qa_digest, sha + 3, sizeof(header.qa_digest));

	uint8_t largekey[0x40];

	keyToContext(header.qa_digest, largekey);
	setContextNum(largekey);
	pkg_crypt(largekey, header.k_licensee, sizeof(header.k_licensee));

	keyToContext(header.qa_digest, largekey);
	pkg_crypt(largekey, pkg_einfo.qa_digest, sizeof(pkg_einfo.qa_digest));

	SHA1((uint8_t*)&header, sizeof(header), sha);
	memcpy(header_crypt.shash, sha + 3, sizeof(header_crypt.shash));
	keyToContext(header_crypt.shash, largekey);
	pkg_crypt(largekey, header_crypt.crypt, sizeof(header_crypt.crypt));

	SHA1((uint8_t*)&pkg_info, sizeof(pkg_info), sha);
	memcpy(pkg_info_crypt.shash, sha + 3, sizeof(pkg_info_crypt.shash));
	keyToContext(pkg_info_crypt.shash, largekey);
	pkg_crypt(largekey, pkg_info_crypt.crypt, sizeof(pkg_info_crypt.crypt));

	keyToContext(header.qa_digest, largekey);
	pkg_crypt(largekey, pkg_data, _ES64(header.data_size));
	
	SHA1(pkg_data, _ES64(header.data_size), sha);
	memcpy(pkg_data_crypt.shash, sha + 3, sizeof(pkg_data_crypt.shash));
	keyToContext(pkg_data_crypt.shash, largekey);
	pkg_crypt(largekey, pkg_data_crypt.crypt, sizeof(pkg_data_crypt.crypt));

	SHA1_Init(&ctx_sha1);
	SHA1_Update(&ctx_sha1, (uint8_t*)&header, sizeof(header));
	SHA1_Update(&ctx_sha1, (uint8_t*)&header_crypt, sizeof(header_crypt));
	SHA1_Update(&ctx_sha1, (uint8_t*)&pkg_info, sizeof(pkg_info));
	SHA1_Update(&ctx_sha1, (uint8_t*)&pkg_einfo, sizeof(pkg_einfo));
	SHA1_Update(&ctx_sha1, (uint8_t*)&pkg_info_crypt, sizeof(pkg_info_crypt));
	SHA1_Update(&ctx_sha1, pkg_data, _ES64(header.data_size));
	SHA1_Update(&ctx_sha1, (uint8_t*)&pkg_data_crypt, sizeof(pkg_data_crypt));

	if(size_fix != NULL)
	{
		SHA1_Update(&ctx_sha1, size_fix, pad_size);
	}

	SHA1_Final(footer.data_sha1, &ctx_sha1);

	char digest[sizeof(header.qa_digest) * 2];
	hexstr(digest, header.qa_digest, sizeof(header.qa_digest));
	printf(" PKG QA_Digest: %s\n", digest);

	hexstr(digest, pkg_einfo.qa_digest, sizeof(pkg_einfo.qa_digest));
	printf(" PKG QA_Digest2: %s\n", digest);

	/*char klicensee[sizeof(header.k_licensee) * 2];
	hexstr(klicensee, header.k_licensee, sizeof(header.k_licensee));
	printf(" PKG K_Licensee (crypt): %s\n", klicensee);*/

	char data_sha1[sizeof(footer.data_sha1) * 2];
	hexstr(data_sha1, footer.data_sha1, sizeof(footer.data_sha1) - 0xc);
	printf(" PKG Digest: %s\n", data_sha1);

	// write pkg
	printf("PKG built - writing to file ...\n");

	FILE* filep = fopen(argv[3], "wb");

	if(filep == NULL)
	{
		perror("error");
		return 1;
	}

	fwrite((uint8_t*)&header, 1, sizeof(header), filep);
	fwrite((uint8_t*)&header_crypt, 1, sizeof(header_crypt), filep);
	fwrite((uint8_t*)&pkg_info, 1, sizeof(pkg_info), filep);
	fwrite((uint8_t*)&pkg_einfo, 1, sizeof(pkg_einfo), filep);
	fwrite((uint8_t*)&pkg_info_crypt, 1, sizeof(pkg_info_crypt), filep);
	fwrite(pkg_data, 1, _ES64(header.data_size), filep);
	fwrite((uint8_t*)&pkg_data_crypt, 1, sizeof(pkg_data_crypt), filep);

	if(size_fix != NULL)
	{
		fwrite(size_fix, 1, pad_size, filep);
	}

	fwrite((uint8_t*)&footer, 1, sizeof(footer), filep);
	fclose(filep);

	printf("PKG file successfully written.\n");
	return 0;
}
