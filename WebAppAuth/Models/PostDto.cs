using System;

namespace WebAppAuth.Models;

    public class PostDto
    {
        public string Title { get; set; }
        public string Content { get; set; }
        public bool IsPublished { get; set; }
    }
