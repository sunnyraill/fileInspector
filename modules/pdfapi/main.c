#include <stdio.h>
#include <mupdf/fitz.h>
#include <mupdf/pdf.h>

typedef struct PDFInfo_s {
    fz_context* ctx;
    pdf_document* pdfdoc;
} PDFInfo;

typedef struct attachment_s {
    unsigned char* data;
    size_t len;
} PDFAttachment;

typedef struct attachment_array_s {
    PDFAttachment* attachments;
    size_t len;
} PDFAttachmentArray;

void getAttachments(PDFInfo * pdf_info, PDFAttachmentArray * attachment_arr) {
    fz_context* ctx = pdf_info->ctx;
    pdf_document* pdfdoc = pdf_info->pdfdoc;
    int attachment_length = 0;
    int i = 0;
    PDFAttachment* pdf_attachments = NULL;

    pdf_obj* attachments = pdf_load_name_tree(ctx, pdfdoc, PDF_NAME(EmbeddedFiles));
    attachment_length = pdf_dict_len(ctx, attachments);

    pdf_attachments = (PDFAttachment*)malloc(attachment_length * sizeof(PDFAttachment));
    if (!pdf_attachments) fprintf(stderr, "cannot create pdf_attachments: seems like no memory left\n");

    for (i = 0; i < attachment_length; i++)
    {
        const char* fileName = pdf_to_name(ctx, pdf_dict_get_key(ctx, attachments, i));
        pdf_obj* value = (pdf_dict_get_val(ctx, attachments, i));
        if (pdf_is_dict(ctx, value)) {
            pdf_obj* ef = pdf_dict_get(ctx, value, PDF_NAME(EF));
            pdf_obj* f = pdf_dict_get(ctx, ef, PDF_NAME(F));
            if (pdf_is_stream(ctx, f)) {
                fz_buffer* buf = pdf_load_stream(ctx, f);
                unsigned char* data = NULL;
                size_t size = fz_buffer_storage(ctx, buf, data);
                pdf_attachments[i].data = (unsigned char*)malloc(size * sizeof(unsigned char));
                pdf_attachments[i].len = fz_buffer_storage(ctx, buf, data);
                if(!pdf_attachments[i].data) fprintf(stderr, "cannot create unsigned char for pdf attahcment: seems like no memory left\n");
            }
        }

    }
    
    attachment_arr->attachments = pdf_attachments;
    pdf_attachments->len = attachment_length;
}


int openPdf(char* filename, char* password, PDFInfo * pdf_info) {
    fz_context* ctx = NULL;
    pdf_document* pdfdoc = NULL;
    fz_page* page = NULL;

    int page_count, i;

    /* Initialize the MuPDF context */
    ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
    if (!ctx)
    {
        fprintf(stderr, "cannot create mupdf context\n");
        return EXIT_FAILURE;
    }

    /* Register the default file types to handle. */
    fz_try(ctx)
        fz_register_document_handlers(ctx);
    fz_catch(ctx)
    {
        fprintf(stderr, "cannot register document handlers: %s\n", fz_caught_message(ctx));
        fz_drop_context(ctx);
        return EXIT_FAILURE;
    }

    fz_try(ctx) {
        pdfdoc = pdf_open_document(ctx, filename);
        if (pdf_needs_password(ctx, pdfdoc))
            if (!pdf_authenticate_password(ctx, pdfdoc, password))
                fz_throw(ctx, FZ_ERROR_GENERIC, "cannot authenticate password: %s", password);
    }fz_catch(ctx) {
        fprintf(stderr, "Error: cannot open PDF document '%s'\n", password);
    }

    if (!pdfdoc) {
        fz_drop_context(ctx);
        return 1;
    }



    /* Print some basic information about the document */
    page_count = pdf_count_pages(ctx, pdfdoc);
    printf("Document '%s' contains %d pages\n", filename, page_count);

    pdf_info->ctx = ctx;
    pdf_info->pdfdoc = pdfdoc;

    return 0;
}

void free_attahcments(PDFAttachmentArray* attahments_array) {
    if (!attahments_array->attachments) return;
    for (int i = 0; i < attahments_array->len; i++) {
        
        if (attahments_array->attachments[i].data) {
            free(attahments_array->attachments[i].data);
        }
    }
    free(attahments_array->attachments);
    attahments_array->attachments = NULL;
    attahments_array->len = 0;
}

void closeDocument(PDFInfo* pdf_info) {

    if (!pdf_info) return;

    if (pdf_info->pdfdoc && pdf_info->ctx)
        pdf_drop_document(pdf_info->ctx, pdf_info->pdfdoc);

    if (pdf_info->ctx)
        fz_drop_context(pdf_info->ctx);


}

int main(int argc, char** argv) {
    PDFInfo pdf_info = {NULL, NULL};
    PDFAttachmentArray attachment_array = {NULL, 0};

    openPdf(argv[1], argv[2], &pdf_info);

    //could be potential multhreading issue: the memory allocated on a thread must be freed from thread.
    getAttachments(&pdf_info, &attachment_array);

    //transfer the attachments here.

    free_attahcments(&attachment_array);

    closeDocument(&pdf_info);

}

int main2(int argc, char** argv)
{
    fz_context* ctx = NULL;
    fz_document* doc = NULL;
    pdf_document* pdfdoc = NULL;
    fz_page* page = NULL;
    char *password = argv[2];
    fz_outline* outline = NULL;

    pdf_obj* attachment_list = NULL;

    int page_count, i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input.pdf>\n", argv[0]);
        return 1;
    }

    /* Initialize the MuPDF context */
    ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
    if (!ctx)
    {
        fprintf(stderr, "cannot create mupdf context\n");
        return EXIT_FAILURE;
    }

    /* Register the default file types to handle. */
    fz_try(ctx)
        fz_register_document_handlers(ctx);
    fz_catch(ctx)
    {
        fprintf(stderr, "cannot register document handlers: %s\n", fz_caught_message(ctx));
        fz_drop_context(ctx);
        return EXIT_FAILURE;
    }

    fz_try(ctx) {
        printf("%s", argv[1]);
        pdfdoc = pdf_open_document(ctx, argv[1]);
        if (pdf_needs_password(ctx, pdfdoc))
            if (!pdf_authenticate_password(ctx, pdfdoc, password))
                fz_throw(ctx, FZ_ERROR_GENERIC, "cannot authenticate password: %s", argv[2]);
    }fz_catch(ctx) {
        fprintf(stderr, "Error: cannot open PDF document '%s'\n", argv[1]);
    }

    /* Open the PDF document */
    if (!pdfdoc) {
       
        fz_drop_context(ctx);
        return 1;
    }

    

    /* Print some basic information about the document */
    page_count = pdf_count_pages(ctx, pdfdoc);
    printf("Document '%s' contains %d pages\n", argv[1], page_count);
    
    {
        pdf_obj* attachments = pdf_load_name_tree(ctx, pdfdoc, PDF_NAME(EmbeddedFiles));
        int len = pdf_dict_len(ctx, attachments);
        for (i = 0; i < len; i++)
        {
            const char * fileName = pdf_to_name(ctx,pdf_dict_get_key(ctx, attachments, i));
            pdf_obj* value = (pdf_dict_get_val(ctx, attachments,i));
            if (pdf_is_dict(ctx, value)) {
                pdf_obj* ef = pdf_dict_get(ctx, value, PDF_NAME(EF));
                pdf_obj* f = pdf_dict_get(ctx, ef, PDF_NAME(F));
                    if (pdf_is_stream(ctx, f)) {
                    fz_buffer* buf = pdf_load_stream(ctx, f);
                    unsigned char* data = NULL;
                    size_t size = fz_buffer_storage(ctx, buf, data);
                    int a = 1;
             }
            }
           
        }


    }
    // = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/Names/EmbeddedFiles/Names"));
    //need to find the 

    // Get the root outline item
    outline = fz_load_outline(ctx, doc);

 


    /* Clean up and exit */
    fz_drop_document(ctx, doc);
    fz_drop_context(ctx);
    return 0;
}
